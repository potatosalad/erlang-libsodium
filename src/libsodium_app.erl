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
-module(libsodium_app).
-behaviour(application).

%% Application callbacks
-export([start/2]).
-export([stop/1]).

%%%===================================================================
%%% Application callbacks
%%%===================================================================

start(_Type, _Args) ->
	libsodium_sup:start_link().

stop(_State) ->
	ok.
