%%% % @format
-module(libsodium_sup).
-moduledoc false.
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2015-12-28", modified => "2026-10-26"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

-behaviour(supervisor).

%% OTP callbacks
-export([
    start_link/0
]).
%% supervisor callbacks
-export([
    init/1
]).

%%%=============================================================================
%%% OTP callbacks
%%%=============================================================================

-doc """
Start the application's root supervisor.

The NIF needs no supervised processes; the supervisor anchors the
application so that `libsodium:start/0` and release tooling behave as before.
""".
-spec start_link() -> Result when Result :: supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%%=============================================================================
%%% supervisor callbacks
%%%=============================================================================

-doc false.
-spec init([]) -> Result when Result :: {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{strategy => one_for_one, intensity => 10, period => 10},
    {ok, {SupFlags, []}}.
