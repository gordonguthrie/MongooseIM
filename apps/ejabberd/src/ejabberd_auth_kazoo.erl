%%%----------------------------------------------------------------------
%%% File     : ejabberd_auth_kazoo.erl
%%% Author   : Gordon Guthrie <gordon.guthrie@iptelecom.ie>
%%% Purpose  : Authentication with Kazoo
%%% Written  : 15th June 2013
%%% Original : ejabberd_auth_http 23 Sep 2013
%%%            by Piotr Nosek <piotr.nosek@erlang-solutions.com>
%%%----------------------------------------------------------------------

-module(ejabberd_auth_kazoo).
-author('gordon.guthrie@iptelecom.ie').
%% based on ejabberd_auth_http by
-author('piotr.nosek@erlang-solutions.com').

-behaviour(ejabberd_gen_auth).

%% External exports
-export([start/1,
         stop/1,
         set_password/3,
         authorize/1,
         try_register/3,
         dirty_get_registered_users/0,
         get_vh_registered_users/1,
         get_vh_registered_users/2,
         get_vh_registered_users_number/1,
         get_vh_registered_users_number/2,
         get_password/2,
         get_password_s/2,
         does_user_exist/2,
         remove_user/2,
         remove_user/3,
         store_type/1
        ]).

%% Pre-mongoose_credentials API
-export([check_password/3,
         check_password/5]).

-include("ejabberd.hrl").

-type http_error_atom() :: conflict | not_found | not_authorized | not_allowed.

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

-spec start(binary()) -> ok.
start(Host) ->
  {AuthOpts, AuthHost} 
    = try
        AOpts = ejabberd_config:get_local_option(auth_opts, Host),
        {_, AHost} = lists:keyfind(host, 1, AOpts),
        {AOpts, AHost}
      catch
        error:_Err -> lager:error("Cannot start ejabberd_auth_kazoo "
                                  "because of configuration errors"),
                     exit("config error")
      end,
  PoolSize = proplists:get_value(connection_pool_size, AuthOpts, 10),
  Opts = proplists:get_value(connection_opts, AuthOpts, []),
  ChildMods = [fusco],
  ChildMF = {fusco, start_link},
  ChildArgs = {for_all, [AuthHost, Opts]},

  Args = [pool_name(Host), PoolSize, ChildMods, ChildMF, ChildArgs],
  {ok, _} = supervisor:start_child(ejabberd_sup,
                                   {{ejabberd_auth_http_sup, Host},
                                    {cuesport, start_link, Args},
                                    transient, 
                                    2000, 
                                    supervisor, 
                                    [cuesport | ChildMods]}),
  ok.

-spec store_type(binary()) -> plain.
store_type(_Server) -> plain.

-spec authorize(mongoose_credentials:t()) -> {ok, mongoose_credentials:t()}
                                               | {error, any()}.
authorize(Creds) ->
  ejabberd_auth:authorize_with_check_password(?MODULE, Creds).

-spec check_password(ejabberd:luser(), ejabberd:lserver(), binary()) -> boolean().
check_password(LUser, LServer, Password) ->
  case make_req(check_password, LUser, LServer, Password) of
    {ok, <<"authorised">>} -> true;
    _                      -> false
  end.

-spec check_password(ejabberd:luser(), ejabberd:lserver(), binary(), binary(), fun()) -> false.
check_password(_LUser, _LServer, _Password, _Digest, _DigestGen) -> false.

-spec set_password(ejabberd:luser(), ejabberd:lserver(), binary()) ->
                      not_allowed.
set_password(_LUser, _LServer, _Password) -> not_allowed.

-spec try_register(ejabberd:luser(), ejabberd:lserver(), binary()) ->
                      not_allowed.
try_register(_LUser, _LServer, _Password) -> not_allowed.

-spec dirty_get_registered_users() -> [].
dirty_get_registered_users() ->
  [].

-spec get_vh_registered_users(ejabberd:lserver()) -> [].
get_vh_registered_users(_Server) ->
  [].

-spec get_vh_registered_users(ejabberd:lserver(), list()) -> [].
get_vh_registered_users(_Server, _Opts) ->
  [].

-spec get_vh_registered_users_number(binary()) -> 0.
get_vh_registered_users_number(_Server) ->
  0.

-spec get_vh_registered_users_number(ejabberd:lserver(), list()) -> 0.
get_vh_registered_users_number(_Server, _Opts) ->
  0.

-spec get_password(ejabberd:luser(), ejabberd:lserver()) -> false.
get_password(_LUser, _LServer) -> false.

-spec get_password_s(ejabberd:luser(), ejabberd:lserver()) -> binary().
get_password_s(_User, _Server) -> <<>>.

-spec does_user_exist(ejabberd:luser(), ejabberd:lserver()) -> boolean().
does_user_exist(_LUser, _LServer) ->
  case make_req(does_user_exist, _LUser, _LServer, <<"">>) of
    {ok, <<"true">>} -> true;
    _                -> false
  end.

-spec remove_user(ejabberd:luser(), ejabberd:lserver()) ->
                     not_allowed.
remove_user(_LUser, _LServer) -> not_allowed.

-spec remove_user(ejabberd:luser(), ejabberd:lserver(), binary()) ->
                     not_allowed.
remove_user(_LUser, _LServer, _Password) -> not_allowed.

%%%----------------------------------------------------------------------
%%% Request maker
%%%----------------------------------------------------------------------

-spec make_req(check_password | does_user_exists, binary(), binary(), binary()) ->
                  {ok, BodyOrCreated :: binary() | created} 
                    | {error, invalid_jid | http_error_atom() | binary()}.
make_req(_, LUser, LServer, _) when LUser == error orelse LServer == error ->
  {error, invalid_jid};
make_req(check_password, LUser, LServer, Password) ->
  AuthOpts = ejabberd_config:get_local_option(auth_opts, LServer),
  case get_kazoo_auth_token(LServer, AuthOpts) of
    {ok, KazooAuthToken} ->
      check_user_credentials(KazooAuthToken, LServer, AuthOpts, LUser, Password);
    {error, "credentials not authorised"} ->
      lager:error("The kazoo authorize token is invalid"),
      not_authorized
  end.

%%%----------------------------------------------------------------------
%%% Other internal functions
%%%----------------------------------------------------------------------

check_user_credentials(KazooAuthToken, LServer, AuthOpts, UserId, Password) ->
  Realm  = proplists:get_value(realm, AuthOpts, ""),
  MD5PasswordHash = to_hex_binary(crypto:hash(md5, Password)),
  Connection = cuesport:get_worker(existing_pool_name(LServer)),
  Path = filename:join([
                        "/v1/ejabberd_auth", 
                        Realm, 
                        "username", 
                        UserId, 
                        "password", 
                        MD5PasswordHash
                       ]),
  Headers = [{<<"X-Auth-Token">>, KazooAuthToken}],
  Timeout_in_ms = 5000,
  case fusco:request(Connection, Path, "GET", Headers, [], 2, Timeout_in_ms) of
    {ok, {{<<"200">>, _Reason}, _Headers, _Resp, _, __}} ->
      {ok, <<"authorised">>};
    {ok, {{<<"401">>, <<"Unauthorized">>}, _Headers, _Body, _, _}} ->
      {error, invalid_jid};
    Error ->
      lager:error("User authorisation failing because of unexpected "
                  "http error ~p", [Error]),
      {error, not_authorised}
  end.

-spec get_kazoo_auth_token(string(), list()) -> {ok, string()} | {error, string()}.
get_kazoo_auth_token(LServer, AuthOpts) ->
  KazooUserId = proplists:get_value(username, AuthOpts, ""),
  KazooPasswd = proplists:get_value(password, AuthOpts, ""),
  KazooRealm  = proplists:get_value(realm,    AuthOpts, ""),
  Realm = list_to_binary(KazooRealm),
  MD5 = crypto:hash(md5, KazooUserId ++ ":" ++ KazooPasswd),
  Credentials = list_to_binary([io_lib:format("~2.16.0b", [B]) 
                                || <<B>> <= MD5]),
  Json = jiffy:encode({
                        [
                         {<<"data">>, {[
                                        {<<"credentials">>, Credentials},
                                        {<<"realm">>,       Realm}
                                       ]}}
                        ]
                      }),
  Connection = cuesport:get_worker(existing_pool_name(LServer)),
  EmptyHeaders = [],
  Timeout_in_ms = 5000,
  case fusco:request(Connection, <<"/v1/user_auth">>, "PUT", 
                     EmptyHeaders, Json, Timeout_in_ms) of
    {ok, {{<<"201">>, _Reason}, _Headers, Body, _, __}} ->
      {JsonResp} = jiffy:decode(Body),
      {<<"auth_token">>, ATok} = lists:keyfind(<<"auth_token">>, 1, JsonResp),
      {ok, ATok};
    {ok, {{<<"401">>, <<"Unauthorized">>}, _Headers, _Body, _, _}} ->
      lager:error("Server configuration for kazoo in ejabberd.cfg is invalid"),
      {error, "credentials not authorised"};
    Error ->
      lager:error("Server configuration for kazoo in ejabberd.cfg leads to "
                  "an error ~p", [Error]),
      {error, "credentials not authorised"}
  end.

-spec pool_name(binary()) -> atom().
pool_name(Host) ->
  list_to_atom("ejabberd_auth_http_" ++ binary_to_list(Host)).

-spec existing_pool_name(binary()) -> atom().
existing_pool_name(Host) ->
  list_to_existing_atom("ejabberd_auth_http_" ++ binary_to_list(Host)).

stop(Host) ->
  Id = {ejabberd_auth_http_sup, Host},
  supervisor:terminate_child(ejabberd_sup, Id),
  supervisor:delete_child(ejabberd_sup, Id),
  ok.

%% These two stolen from kz_util.erl in kazoo/core
-spec to_hex_binary(binary()) -> binary().
to_hex_binary(Bin) when is_binary(Bin)->
    << <<(binary_to_hex_char(B div 16)), (binary_to_hex_char(B rem 16))>> 
       || <<B>> <= Bin>>.

-spec binary_to_hex_char(pos_integer()) -> pos_integer().
binary_to_hex_char(N) when N < 10 -> $0 + N;
binary_to_hex_char(N) when N < 16 -> $a - 10 + N.
