%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  24 May 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_pwhash_argon2i).

-define(NAMESPACE, crypto_pwhash_argon2i).

%% API
-export([alg_argon2i13/0]).
-export([saltbytes/0]).
-export([strbytes/0]).
-export([strprefix/0]).
-export([opslimit_interactive/0]).
-export([memlimit_interactive/0]).
-export([opslimit_moderate/0]).
-export([memlimit_moderate/0]).
-export([opslimit_sensitive/0]).
-export([memlimit_sensitive/0]).
-export([crypto_pwhash_argon2i/6]).
-export([str/3]).
-export([str_verify/2]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

alg_argon2i13() ->
	call(alg_argon2i13).

saltbytes() ->
	call(saltbytes).

strbytes() ->
	call(strbytes).

strprefix() ->
	call(strprefix).

opslimit_interactive() ->
	call(opslimit_interactive).

memlimit_interactive() ->
	call(memlimit_interactive).

opslimit_moderate() ->
	call(opslimit_moderate).

memlimit_moderate() ->
	call(memlimit_moderate).

opslimit_sensitive() ->
	call(opslimit_sensitive).

memlimit_sensitive() ->
	call(memlimit_sensitive).

crypto_pwhash_argon2i(Outlen, Passwd, Salt, Opslimit, Memlimit, Alg)
		when (is_integer(Outlen) andalso Outlen >= 0)
		andalso is_binary(Passwd)
		andalso is_binary(Salt)
		andalso (is_integer(Opslimit) andalso Opslimit >= 0)
		andalso (is_integer(Memlimit) andalso Memlimit >= 0)
		andalso is_integer(Alg) ->
	call(crypto_pwhash_argon2i, {Outlen, Passwd, Salt, Opslimit, Memlimit, Alg}).

str(Passwd, Opslimit, Memlimit)
		when is_binary(Passwd)
		andalso (is_integer(Opslimit) andalso Opslimit >= 0)
		andalso (is_integer(Memlimit) andalso Memlimit >= 0) ->
	call(str, {Passwd, Opslimit, Memlimit}).

str_verify(Str, Passwd)
		when is_binary(Str)
		andalso is_binary(Passwd) ->
	call(str_verify, {Str, Passwd}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
