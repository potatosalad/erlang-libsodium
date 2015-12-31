%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  31 Dec 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_aead_aes256gcm).

-define(NAMESPACE, crypto_aead_aes256gcm).

%% API
-export([is_available/0]).
-export([keybytes/0]).
-export([nsecbytes/0]).
-export([npubbytes/0]).
-export([abytes/0]).
-export([statebytes/0]).
-export([encrypt/3]).
-export([encrypt/4]).
-export([decrypt/3]).
-export([decrypt/4]).
% -export([beforenm/1]).
% -export([encrypt_afternm/3]).
% -export([encrypt_afternm/4]).
% -export([decrypt_afternm/3]).
% -export([decrypt_afternm/4]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

is_available() ->
	call(is_available).

keybytes() ->
	call(keybytes).

nsecbytes() ->
	call(nsecbytes).

npubbytes() ->
	call(npubbytes).

abytes() ->
	call(abytes).

statebytes() ->
	call(statebytes).

encrypt(M, NPub, K)
		when is_binary(M)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	encrypt(M, <<>>, NPub, K).

encrypt(M, AD, NPub, K)
		when is_binary(M)
		andalso is_binary(AD)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	call(encrypt, {M, AD, <<>>, NPub, K}).

decrypt(C, NPub, K)
		when is_binary(C)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	decrypt(C, <<>>, NPub, K).

decrypt(C, AD, NPub, K)
		when is_binary(C)
		andalso is_binary(AD)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	call(decrypt, {<<>>, C, AD, NPub, K}).

% beforenm(K)
% 		when is_binary(K) ->
% 	call(beforenm, {K}).

% encrypt_afternm(M, NPub, CTX)
% 		when is_binary(M)
% 		andalso is_binary(NPub)
% 		andalso is_binary(CTX) ->
% 	encrypt_afternm(M, <<>>, NPub, CTX).

% encrypt_afternm(M, AD, NPub, CTX)
% 		when is_binary(M)
% 		andalso is_binary(AD)
% 		andalso is_binary(NPub)
% 		andalso is_binary(CTX) ->
% 	call(encrypt_afternm, {M, AD, <<>>, NPub, CTX}).

% decrypt_afternm(C, NPub, CTX)
% 		when is_binary(C)
% 		andalso is_binary(NPub)
% 		andalso is_binary(CTX) ->
% 	decrypt_afternm(C, <<>>, NPub, CTX).

% decrypt_afternm(C, AD, NPub, CTX)
% 		when is_binary(C)
% 		andalso is_binary(AD)
% 		andalso is_binary(NPub)
% 		andalso is_binary(CTX) ->
% 	call(decrypt_afternm, {<<>>, C, AD, NPub, CTX}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
