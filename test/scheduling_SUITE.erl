%%% % @format
-module(scheduling_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Common Test coverage for NIF scheduling.

With a single normal scheduler online, a process measures its own wakeup
latency while another process runs a long native operation. Large one-shot
calls must move to a dirty scheduler and streaming updates must yield, so the
measuring process keeps running promptly in both cases.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2026-10-26", modified => "2026-10-26"}.
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1
]).

%% Tests.
-export([
    dirty_one_shot/1,
    dirty_output/1,
    dirty_password_hash/1,
    yielding_update/1
]).

%% Input large enough that a non-yielding call would stall a scheduler for a long time.
-define(LARGE, (256 * 1024 * 1024)).

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        dirty_one_shot,
        dirty_output,
        dirty_password_hash,
        yielding_update
    ].

-spec init_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libsodium),
    Online = erlang:system_flag(schedulers_online, 1),
    [{schedulers_online, Online} | Config].

-spec end_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
end_per_suite(Config) ->
    _ = erlang:system_flag(schedulers_online, ?config(schedulers_online, Config)),
    _ = application:stop(libsodium),
    ok.

%%%=============================================================================
%%% Tests
%%%=============================================================================

-spec dirty_one_shot(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
dirty_one_shot(_Config) ->
    Key = libsodium_crypto_secretbox:keygen(),
    Nonce = libsodium_randombytes:buf(libsodium_crypto_secretbox:noncebytes()),
    Message = binary:copy(<<0>>, ?LARGE),
    Ciphertext = assert_responsive(fun() -> libsodium_crypto_secretbox:easy(Message, Nonce, Key) end),
    Message = libsodium_crypto_secretbox:open_easy(Ciphertext, Nonce, Key),
    ok.

-spec dirty_output(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
dirty_output(_Config) ->
    Bytes = assert_responsive(fun() -> libsodium_randombytes:buf(?LARGE) end),
    ?LARGE = byte_size(Bytes),
    ok.

-spec dirty_password_hash(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
dirty_password_hash(_Config) ->
    Hash = assert_responsive(fun() ->
        libsodium_crypto_pwhash:str(
            <<"password">>,
            libsodium_crypto_pwhash:opslimit_moderate(),
            libsodium_crypto_pwhash:memlimit_moderate()
        )
    end),
    0 = libsodium_crypto_pwhash:str_verify(Hash, <<"password">>),
    ok.

-spec yielding_update(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
yielding_update(_Config) ->
    Input = binary:copy(<<1>>, ?LARGE),
    Init =
        case libsodium_crypto_generichash:init() of
            Failed when is_integer(Failed) -> ct:fail({init_failed, Failed});
            Init0 -> Init0
        end,
    State = assert_responsive(fun() -> libsodium_crypto_generichash:update(Init, Input) end),
    Digest = libsodium_crypto_generichash:final(State),
    Digest = libsodium_crypto_generichash:crypto_generichash(Input),
    ok.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% Run Fun in a separate process and fail if a 1 ms timer in this process is
%% delayed by more than a quarter of Fun's run time (and at least 50 ms).
-spec assert_responsive(Fun) -> Result when Fun :: fun(() -> Result), Result :: dynamic().
assert_responsive(Fun) ->
    Parent = self(),
    Started = erlang:monotonic_time(millisecond),
    {Pid, Monitor} = spawn_monitor(fun() -> Parent ! {self(), result, Fun()} end),
    {Result, MaxGap} = wait(Pid, Monitor, Started, 0),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    ct:log("elapsed ~B ms, longest timer delay ~B ms", [Elapsed, MaxGap]),
    case MaxGap =< max(50, Elapsed div 4) of
        true -> Result;
        false -> ct:fail({scheduler_blocked, #{elapsed_ms => Elapsed, max_gap_ms => MaxGap}})
    end.

-spec wait(Pid, Monitor, Last, MaxGap) -> {Result, MaxGap} when
    Pid :: pid(), Monitor :: reference(), Last :: integer(), MaxGap :: non_neg_integer(), Result :: dynamic().
wait(Pid, Monitor, Last, MaxGap) ->
    receive
        {Pid, result, Result} ->
            receive
                {'DOWN', Monitor, process, Pid, _} -> ok
            end,
            {Result, MaxGap};
        {'DOWN', Monitor, process, Pid, Reason} ->
            ct:fail({worker_crashed, Reason})
    after 1 ->
        Now = erlang:monotonic_time(millisecond),
        wait(Pid, Monitor, Now, max(MaxGap, Now - Last))
    end.
