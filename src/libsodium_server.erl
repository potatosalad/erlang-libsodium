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
-module(libsodium_server).

-include("libsodium.hrl").

-behaviour(gen_server).

%% Public API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

%% Private API
-export([load/0]).
-export([unload/0]).

%% Records
-record(state, {
	port = undefined :: undefined | port()
}).

%%%===================================================================
%%% Public API
%%%===================================================================

-spec start_link()
	-> {ok, pid()} | ignore | {error, term()}.
start_link() ->
	gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init([])
	-> ignore | {ok, #state{}} | {stop, any()}.
init([]) ->
	erlang:process_flag(trap_exit, true),
	case load() of
		ok ->
			Port = erlang:open_port({spawn_driver, ?LIBSODIUM_DRIVER_NAME}, [binary]),
			erlang:register(?LIBSODIUM_DRIVER_ATOM, Port),
			State = #state{port=Port},
			{ok, State};
		{error, LoadError} ->
			LoadErrorStr = erl_ddll:format_error(LoadError),
			ErrorStr = lists:flatten(io_lib:format(
				"could not load driver ~s: ~p",
				[?LIBSODIUM_DRIVER_NAME, LoadErrorStr])),
			{stop, ErrorStr}
	end.

-spec handle_call(any(), {pid(), any()}, #state{})
	-> {reply, any(), #state{}}.
handle_call(_Request, _From, State) ->
	{reply, ok, State}.

-spec handle_cast(any(), #state{})
	-> {noreply, #state{}} | {stop, any(), #state{}}.
handle_cast(stop, State) ->
	{stop, normal, State};
handle_cast(_Msg, State) ->
	{noreply, State}.

-spec handle_info(any(), #state{})
	-> {noreply, #state{}}.
handle_info(_Info, State) ->
	{noreply, State}.

-spec terminate(any(), #state{})
	-> ok.
terminate(_Reason, #state{port=Port}) ->
	erlang:unregister(?LIBSODIUM_DRIVER_ATOM),
	erlang:port_close(Port),
	ok.

-spec code_change(any(), #state{}, any())
	-> {ok, #state{}}.
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%%%===================================================================
%%% Private API
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Load port driver
%% @end
%%--------------------------------------------------------------------
-spec load() -> ok | {error, any()}.
load() ->
	{ok, Drivers} = erl_ddll:loaded_drivers(),
	case lists:member(?LIBSODIUM_DRIVER_NAME, Drivers) of
		true ->
			ok;
		false ->
			case erl_ddll:load(priv_dir(), ?LIBSODIUM_DRIVER_NAME) of
				ok ->
					ok;
				{error, already_loaded} ->
					ok;
				{error, Error} ->
					error_logger:error_msg(
						?MODULE_STRING ": Error loading ~p: ~p~n",
						[?LIBSODIUM_DRIVER_NAME, erl_ddll:format_error(Error)]
					),
					{error, Error}
			end
	end.

%%--------------------------------------------------------------------
%% @private
%% @doc Unload port driver
%% @end
%%--------------------------------------------------------------------
-spec unload() -> ok | {error, any()}.
unload() ->
	case erl_ddll:unload_driver(?LIBSODIUM_DRIVER_NAME) of
		ok ->
			ok;
		{error, Error} ->
			error_logger:error_msg(
				?MODULE_STRING ": Error unloading ~p: ~p~n",
				[?LIBSODIUM_DRIVER_NAME, erl_ddll:format_error(Error)]
			),
			{error, Error}
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
priv_dir() ->
	case code:priv_dir(libsodium) of
		{error, bad_name} ->
			case code:which(?MODULE) of
				Filename when is_list(Filename) ->
					filename:join([filename:dirname(Filename), "../priv"]);
				_ ->
					"../priv"
			end;
		Dir ->
			Dir
	end.
