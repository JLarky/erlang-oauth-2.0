%%% @author JLarky <jlarky@punklan.net>
%%% @copyright (C) 2011, JLarky
%%% @doc
%%% OAuth 2.0 provider/client interface
%%% @end
%%% Created : 27 Nov 2011 by JLarky <jlarky@punklan.net>

-module(erl_oauth2).
-define(CODE_EXPIRE, 10). %% min
-define(DEFAULT_TOKEN_EXPIRE, 60). %% min

%% provider
-export([get_access_denied_url/2,
	 create_grant_perm_url/2,
	 create_auth_code/2,
	 create_access_token/4,
	 verify_token/2]).

%% client
-export([get/2]).

%% helpers
-export([parse_uri_helper/1,
	 random_string/0]).

-export_type([database_type/0,orddict/0]).

%% behaviour
-export([behaviour_info/1]).

behaviour_info(callbacks) -> [{get_orddict_by_key, 2},
			      {set_orddict_by_key, 3},
			      {remove_by_key, 2}];
behaviour_info(_Other) -> undefined.

-type database_type() :: token | app | code.
-type orddict()   :: [{term(), term()}].
-type proplists() :: [{term(), term()}].

%% CLIENT

-spec get(string(), proplists()) -> proplists() | {error, term()}.
get(Url, Params) ->
    URL = Url++"?"++mochiweb_util:urlencode(Params),
    case send_request(URL) of
	{ok, {struct, PropList}} ->
	    [ {binary_to_list(X), Y} || {X,Y} <- PropList ];
	{ok, NotObjectJSON} ->
	    {error, {json, NotObjectJSON}};
	{ok, Type, NotJSON} ->
	    {error, {Type, NotJSON}};
	Error ->
	    {error, Error}
    end.

%% PROVIDER
-spec get_access_denied_url(atom(), proplists()) -> string() | {error, term()}.
get_access_denied_url(DBModule, PropList) ->
    case proplists:get_value("client_id", PropList) of
	undefined ->
	    {error, wrong_client_id};
	ClientId ->
	    ClientIdBin = list_to_binary(ClientId),
	    Type = app, Key = ClientIdBin,
	    ClientDict = DBModule:get_orddict_by_key(Type, Key),
	    RedirectURI = get_redirect_uri(ClientDict, PropList),
	    Query =
		[{error_reason, user_denied},
		 {error, access_denied},
		 {error_description, "The user denied your request"}],
	    case RedirectURI of
		{error, Error} -> {error, Error};
		_ -> redirect_uri_helper(RedirectURI, Query)
	    end
    end.

-spec create_grant_perm_url(atom(), proplists()) -> string() | {error, term()}.
create_grant_perm_url(DBModule, PropList) ->
    Query1 =
	case proplists:get_value("state", PropList) of
	    undefined -> [];
	    State     -> [{state, State}]
	end,
    case proplists:get_value("client_id", PropList) of
	undefined ->
	    {error, wrong_client_id};
	ClientId ->
	    ClientIdBin = list_to_binary(ClientId),
	    Type = app, Key = ClientIdBin,
	    ClientDict = DBModule:get_orddict_by_key(Type, Key),
	    case orddict:is_key(secret, ClientDict) andalso
		 orddict:is_key(redirect_uri, ClientDict) of
		false ->
		    {error, wrong_client_id};
		true ->
		    CodeDict = orddict:from_list([{app_id, ClientId},
						  {used, false}]),
		    case create_auth_code(DBModule, CodeDict) of
			{error, Error} -> {error, Error};
			Code ->
			    RedirectURI = get_redirect_uri(ClientDict, PropList),
			    Query = [{code, Code}] ++ Query1,
			    redirect_uri_helper(RedirectURI, Query)
		    end
	    end
    end.

-spec create_auth_code(atom(), orddict()) -> string() | {error, term()}.
create_auth_code(DBModule, CodeDict) ->
    AuthCode = random_string(),
    AuthCodeBin = list_to_binary(AuthCode),
    Type = code, Key = AuthCodeBin,
    CodeDict1 = orddict:store(time, now(), CodeDict),
    case DBModule:set_orddict_by_key(Type, Key, CodeDict1) of
	ok -> AuthCode;
	{error, Error} ->
	    {error, Error}
    end.

%% api
-spec create_access_token(database_type(), string(), string(), string()) -> proplists() | {error, term()}.
create_access_token(DBModule, AppId, AppSecret, Code) ->
    case (catch access_token_(DBModule, AppId, AppSecret, Code)) of
	TokenPropList when is_list(TokenPropList) -> TokenPropList;
	{error, code_expired} ->
	    {error, {400, [{error, invalid_grant},
			   {error_description, "Code expired"}]}};
	{error, Error} -> {error, Error};
	Error -> {error, Error}
    end.

access_token_(DBModule, AppId, AppSecret, Code) ->
    case lists:all(fun(E) -> E =/= undefined end, [AppId, AppSecret, Code]) of
	true -> ok;
	false -> throw({error, wrong_arguments})
    end,
    CodeBin = list_to_binary(Code),
    Type = code, Key = Code,
    CodeDict = DBModule:get_orddict_by_key(Type, Key),
    case orddict:is_key(time, CodeDict) of
	true -> ok;
	false -> throw({error, wrong_code})
    end,
    Time = orddict:fetch(time, CodeDict),
    CodeExpire = time_diff(Time, now()) > ?CODE_EXPIRE*60,
    case CodeExpire of
	false -> ok;
	true ->
	    DBModule:remove_by_key(code, CodeBin),
	    throw({error, code_expired})
    end,
    %% so code is good
    AppIdBin = list_to_binary(AppId),
    AppDict = DBModule:get_orddict_by_key(app, AppIdBin),
    case orddict:is_key(secret, AppDict) of
	true -> ok;
	false -> throw({error, wrong_app_id})
    end,
    case orddict:fetch(secret, AppDict) =:= AppSecret of
	true -> ok;
	false -> throw({error, wrong_app_secret})
    end,
    %% so app id and secret is good
    Expire = 60*?DEFAULT_TOKEN_EXPIRE,

    Token = random_string(),
    TokenBin = list_to_binary(Token),
    TokenDict =  orddict:from_list([{client_id,AppIdBin},
				    {expires_in, Expire},
				    {time,now()}]),
    DBModule:remove_by_key(code, CodeBin),
    DBModule:set_orddict_by_key(token, TokenBin, TokenDict),
    [{access_token, Token},
     {token_type, "example"},
     {expires_in, Expire},
     {test_param, "test_value"}].

-spec verify_token(database_type(), string()) -> true | {error, term()}.
verify_token(DBModule, Token) ->
    Type = token, Key = list_to_binary(Token),
    TokenDict = DBModule:get_orddict_by_key(Type, Key),
    case orddict:is_key(time, TokenDict) of
	true ->
	    Time = orddict:fetch(time, TokenDict),
	    Expire =
		case (catch orddict:fetch(expires_in, TokenDict)) of
		    Sec when is_integer(Sec) -> Sec;
		    _error_or_wrong ->
			?DEFAULT_TOKEN_EXPIRE *60
		end,
	    case time_diff(Time, now()) < Expire of
		true  -> true;
		false -> {error, token_expired}
	    end;
	false -> {error, wrong_token}
    end.



%% @private
-spec get_redirect_uri(orddict(), proplists()) -> string() | {error, term()}.
get_redirect_uri(ClientDict, PropList) ->
    case orddict:is_key(redirect_uri, ClientDict) of
	false ->
	    {error, wrong_client_id};
	true ->
	    RU = proplists:get_value("redirect_uri", PropList),
	    ClientRedirectUri = orddict:fetch(redirect_uri, ClientDict),
	    case lists:member(RU, ClientRedirectUri) of
		true -> RU; %% redirect_uri from PropList
		false ->
		    [URL|_] = ClientRedirectUri,
		    URL %% default redirect_url
	    end
    end.

%% HELPERS

-spec parse_uri_helper(string()) -> proplists().
parse_uri_helper(URL) ->
    {_Scheme, _Netloc, _Path, Query, _Fragment} = mochiweb_util:urlsplit(URL),
    mochiweb_util:parse_qs(Query).

-spec redirect_uri_helper(string(), proplists()) -> string().
redirect_uri_helper(RedirectUri, PropList) ->
    {Scheme, Netloc, Path, _Query, _Fragment} = mochiweb_util:urlsplit(RedirectUri),
    Query = mochiweb_util:urlencode(PropList),
    mochiweb_util:urlunsplit({Scheme, Netloc, Path, Query, ""}).

-spec random_string() -> string().
random_string() -> %% random 156 bit string
    Rand = crypto:sha(term_to_binary({make_ref(), now()})),
    <<RandBin:156/bitstring, _:4>> = Rand,
    Chars = list_to_tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"),
    random_string(Chars, RandBin, "").

random_string(_Chars, <<>>, Acc) -> Acc;
random_string(Chars, Rand, Acc) ->
    <<I:6, Rest/bitstring>> = Rand, %% 0 <= I <= 63
    random_string(Chars, Rest, [element(I+1, Chars)|Acc]).


%% @private
send_request(Uri) ->
    case httpc:request(Uri) of
	{ok, {_, Header, Data}} ->
	    case string:tokens(proplists:get_value("content-type", Header), ";") of
		["text/javascript" | _Rest] ->
		    {ok, mochijson2:decode(Data)};
		["application/json" | _Rest] ->
		    {ok, mochijson2:decode(Data)};
		[Type | _Rest] ->
		    {ok, Type, Data}
	    end;
	{error, _} = E ->
	    E
    end.

%% @private
-type now() :: {integer(),integer(),integer()}.
-spec time_diff(now(), now()) -> integer().
time_diff(BaseTime, CurrentTime) ->
    Time = calendar:now_to_datetime(BaseTime),
    Now = calendar:now_to_datetime(CurrentTime),
    Diff = calendar:time_difference(Time, Now),
    {Day, {Hour, Min, Sec}} = Diff,
    Sec + 60*(Min + 60*(Hour+24*Day)).
