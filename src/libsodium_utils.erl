%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  30 Dec 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_utils).

-define(NAMESPACE, utils).

%% API
-export([compare/2]).
-export([is_zero/1]).
-export([increment/1]).
-export([add/2]).
-export([bin2hex/1]).
-export([hex2bin/1]).
-export([hex2bin/2]).
-export([base64_variants/0]).
-export([base64_encoded_len/2]).
-export([bin2base64/1]).
-export([bin2base64/2]).
-export([base642bin/1]).
-export([base642bin/2]).
-export([base642bin/3]).
-export([pad/2]).
-export([unpad/2]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

compare(B1, B2)
		when is_binary(B1)
		andalso is_binary(B2) ->
	call(compare, {B1, B2}).

is_zero(N)
		when is_binary(N) ->
	call(is_zero, {N}).

increment(N)
		when is_binary(N) ->
	call(increment, {N}).

add(A, B)
		when is_binary(A)
		andalso is_binary(B) ->
	call(add, {A, B}).

bin2hex(Bin)
		when is_binary(Bin) ->
	call(bin2hex, {Bin}).

hex2bin(Hex)
		when is_binary(Hex) ->
	hex2bin(Hex, <<>>).

hex2bin(Hex, Ignore)
		when is_binary(Hex)
		andalso is_binary(Ignore) ->
	call(hex2bin, {Hex, Ignore}).

base64_variants() ->
	call(base64_variants).

base64_encoded_len(BinLen, Variant)
		when (is_integer(BinLen) andalso BinLen >= 0)
		andalso ((is_integer(Variant) andalso Variant >= 0) orelse is_atom(Variant)) ->
	call(base64_encoded_len, {BinLen, Variant}).

bin2base64(Bin)
		when is_binary(Bin) ->
	bin2base64(Bin, original).

bin2base64(Bin, Variant)
		when is_binary(Bin)
		andalso ((is_integer(Variant) andalso Variant >= 0) orelse is_atom(Variant)) ->
	call(bin2base64, {Bin, Variant}).

base642bin(B64)
		when is_binary(B64) ->
	base642bin(B64, original).

base642bin(B64, Variant)
		when is_binary(B64)
		andalso ((is_integer(Variant) andalso Variant >= 0) orelse is_atom(Variant)) ->
	base642bin(B64, <<>>, Variant).

base642bin(B64, Ignore, Variant)
		when is_binary(B64)
		andalso is_binary(Ignore)
		andalso ((is_integer(Variant) andalso Variant >= 0) orelse is_atom(Variant)) ->
	call(base642bin, {B64, Ignore, Variant}).

pad(UnpaddedBuf, Blocksize)
		when is_binary(UnpaddedBuf)
		andalso (is_integer(Blocksize) andalso Blocksize >= 0) ->
	call(pad, {UnpaddedBuf, Blocksize}).

unpad(PaddedBuf, Blocksize)
		when is_binary(PaddedBuf)
		andalso (is_integer(Blocksize) andalso Blocksize >= 0) ->
	call(unpad, {PaddedBuf, Blocksize}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
