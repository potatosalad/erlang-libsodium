%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  28 Dec 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium).

-include("libsodium.hrl").

%% API
-export([start/0]).
-export([call/2]).
-export([call/3]).
-export([call/4]).
-export([open/0]).
-export([close/1]).

-define(MAYBE_START_LIBSODIUM(F), try
	F
catch
	_:_ ->
		_ = libsodium:start(),
		F
end).

%%%===================================================================
%%% API
%%%===================================================================

start() ->
	application:ensure_all_started(?MODULE).

call(Namespace, Function)
		when is_atom(Namespace)
		andalso is_atom(Function) ->
	?MAYBE_START_LIBSODIUM(call(Namespace, Function, {})).

call(Namespace, Function, Arguments)
		when is_atom(Namespace)
		andalso is_atom(Function)
		andalso is_tuple(Arguments) ->
	?MAYBE_START_LIBSODIUM(call(erlang:whereis(?LIBSODIUM_DRIVER_ATOM), Namespace, Function, Arguments)).

call(Port, Namespace, Function, Arguments)
		when is_port(Port)
		andalso is_atom(Namespace)
		andalso is_atom(Function)
		andalso is_tuple(Arguments) ->
	driver_call(Port, ?LIBSODIUM_ASYNC_CALL, Namespace, Function, Arguments).

open() ->
	erlang:open_port({spawn_driver, ?LIBSODIUM_DRIVER_NAME}, [binary]).

close(P) ->
	try
		true = erlang:port_close(P),
		receive
			{'EXIT', P, _} ->
				ok
		after
			0 ->
				ok
		end
	catch
		_:_ ->
			erlang:error(badarg)
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
driver_call(Port, Command, Namespace, Function, Arguments) ->
	Tag = erlang:make_ref(),
	case erlang:port_call(Port, Command, {Tag, Namespace, Function, Arguments}) of
		Tag ->
			receive
				{Tag, Reply} ->
					Reply
			end;
		{Tag, Error} ->
			Error
	end.
