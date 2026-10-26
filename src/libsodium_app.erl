%%% % @format
-module(libsodium_app).
-moduledoc false.
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2015-12-28", modified => "2026-10-26"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

-behaviour(application).

%% application callbacks
-export([
    start/2,
    stop/1
]).

%%%=============================================================================
%%% application callbacks
%%%=============================================================================

-doc false.
-spec start(StartType, StartArgs) -> StartResult when
    StartType :: application:start_type(),
    StartArgs :: term(),
    StartResult :: {ok, pid()} | {error, term()}.
start(_StartType, _StartArgs) ->
    case libsodium_sup:start_link() of
        {ok, Pid} -> {ok, Pid};
        {error, Reason} -> {error, Reason};
        ignore -> {error, supervisor_ignored}
    end.

-doc false.
-spec stop(State) -> Ignored when
    State :: term(),
    Ignored :: ok.
stop(_State) ->
    ok.
