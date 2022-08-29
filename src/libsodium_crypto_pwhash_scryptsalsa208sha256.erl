%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  10 Mar 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_pwhash_scryptsalsa208sha256).

-define(NAMESPACE, crypto_pwhash_scryptsalsa208sha256).

%% API
-export([bytes_min/0]).
-export([bytes_max/0]).
-export([passwd_min/0]).
-export([passwd_max/0]).
-export([saltbytes/0]).
-export([strbytes/0]).
-export([strprefix/0]).
-export([opslimit_min/0]).
-export([opslimit_max/0]).
-export([memlimit_min/0]).
-export([memlimit_max/0]).
-export([opslimit_interactive/0]).
-export([memlimit_interactive/0]).
-export([opslimit_sensitive/0]).
-export([memlimit_sensitive/0]).
-export([crypto_pwhash_scryptsalsa208sha256/5]).
-export([str/3]).
-export([str_verify/2]).
-export([ll/6]).
-export([str_needs_rehash/3]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes_min() ->
	call(bytes_min).

bytes_max() ->
	call(bytes_max).

passwd_min() ->
	call(passwd_min).

passwd_max() ->
	call(passwd_max).

saltbytes() ->
	call(saltbytes).

strbytes() ->
	call(strbytes).

strprefix() ->
	call(strprefix).

opslimit_min() ->
	call(opslimit_min).

opslimit_max() ->
	call(opslimit_max).

memlimit_min() ->
	call(memlimit_min).

memlimit_max() ->
	call(memlimit_max).

opslimit_interactive() ->
	call(opslimit_interactive).

memlimit_interactive() ->
	call(memlimit_interactive).

opslimit_sensitive() ->
	call(opslimit_sensitive).

memlimit_sensitive() ->
	call(memlimit_sensitive).

crypto_pwhash_scryptsalsa208sha256(Outlen, Passwd, Salt, Opslimit, Memlimit)
		when (is_integer(Outlen) andalso Outlen >= 0)
		andalso is_binary(Passwd)
		andalso is_binary(Salt)
		andalso (is_integer(Opslimit) andalso Opslimit >= 0)
		andalso (is_integer(Memlimit) andalso Memlimit >= 0) ->
	call(crypto_pwhash_scryptsalsa208sha256, {Outlen, Passwd, Salt, Opslimit, Memlimit}).

str(Passwd, Opslimit, Memlimit)
		when is_binary(Passwd)
		andalso (is_integer(Opslimit) andalso Opslimit >= 0)
		andalso (is_integer(Memlimit) andalso Memlimit >= 0) ->
	call(str, {Passwd, Opslimit, Memlimit}).

str_verify(Str, Passwd)
		when is_binary(Str)
		andalso is_binary(Passwd) ->
	call(str_verify, {Str, Passwd}).

ll(Passwd, Salt, N, R, P, Buflen)
		when is_binary(Passwd)
		andalso is_binary(Salt)
		andalso (is_integer(N) andalso N >= 0)
		andalso (is_integer(R) andalso R >= 0)
		andalso (is_integer(P) andalso P >= 0)
		andalso (is_integer(Buflen) andalso Buflen >= 0) ->
	call(ll, {Passwd, Salt, N, R, P, Buflen}).

str_needs_rehash(Str, Opslimit, Memlimit)
		when is_binary(Str)
		andalso (is_integer(Opslimit) andalso Opslimit >= 0)
		andalso (is_integer(Memlimit) andalso Memlimit >= 0) ->
	call(str_needs_rehash, {Str, Opslimit, Memlimit}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
