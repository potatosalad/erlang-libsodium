%%% % @format
-module(libsodium_ct).
-compile(warn_missing_spec_all).
-moduledoc false.

-include_lib("common_test/include/ct.hrl").

%% API
-export([
    start/2,
    stop/1,
    progress_start/0,
    progress_stop/1
]).

%% Internal API
-export([
    init/1,
    assert_badarg/3,
    call/3,
    halt/1
]).

%% Macros
-define(RED, "\e[0;31m").
-define(GREEN, "\e[0;32m").
-define(YELLOW, "\e[0;33m").
-define(WHITE, "\e[0;37m").
-define(CYAN, "\e[0;36m").
-define(RESET, "\e[0m").
% timer:seconds(1)
-define(TIME, 1000).

-type progress() :: {reference(), pid()}.

-spec start(Group, Config) -> Result when
    Group :: atom(), Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
start(Group, Config) ->
    Now = os:timestamp(),
    io:format(user, "~s[  ] ~s :: ~s~s", [?WHITE, format_utc_timestamp(Now), Group, ?RESET]),
    {ok, Progress} = progress_start(),
    [{libsodium_ct, {Progress, Now}} | Config].

-spec stop(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
stop(Config) ->
    Now = os:timestamp(),
    {Progress, Old} = ?config(libsodium_ct, Config),
    ok = progress_stop(Progress),
    Diff = timer:now_diff(Now, Old),
    io:format(user, "~s[OK] ~s :: ~s elapsed~s~n", [
        ?GREEN, format_utc_timestamp(Now), format_elapsed_time(Diff), ?RESET
    ]),
    ok.

-spec progress_start() -> Result when Result :: {ok, progress()}.
progress_start() ->
    Ref = erlang:make_ref(),
    {ok, Pid} = proc_lib:start(?MODULE, init, [{self(), Ref}]),
    true = is_pid(Pid),
    {ok, {Ref, Pid}}.

-spec progress_stop(Progress) -> Result when Progress :: progress(), Result :: ok.
progress_stop({Ref, Pid}) ->
    Pid ! {stop, self(), Ref},
    receive
        Ref ->
            ok
    after 1000 ->
        ok
    end.

%% @private
-spec format_elapsed_time(Microseconds) -> Result when Microseconds :: integer(), Result :: io_lib:chars().
format_elapsed_time(USec) ->
    Micro = USec rem 1000000,
    Second = ((USec - Micro) div 1000000) rem 60,
    Minute = ((USec - (Second * 1000000)) div 6000000) rem 60,
    Hour = ((USec - (Minute * 6000000)) div 360000000) rem 24,
    io_lib:format("~2..0w:~2..0w:~2..0w.~6..0w", [Hour, Minute, Second, Micro]).

%% @private
-spec format_utc_timestamp(Timestamp) -> Result when Timestamp :: erlang:timestamp(), Result :: io_lib:chars().
format_utc_timestamp(TS = {_, _, Micro}) ->
    {{Year, Month, Day}, {Hour, Minute, Second}} = calendar:now_to_universal_time(TS),
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w.~6..0w", [Year, Month, Day, Hour, Minute, Second, Micro]).

%% @private
-spec init(Parent) -> Result when Parent :: {pid(), reference()}, Result :: no_return().
init({Parent, Ref}) ->
    process_flag(trap_exit, true),
    ok = proc_lib:init_ack(Parent, {ok, self()}),
    {ok, TRef} = timer:send_interval(?TIME, {tick, Ref}),
    loop(Ref, TRef).

%% @private
-spec loop(Reference, Timer) -> Result when Reference :: reference(), Timer :: timer:tref(), Result :: no_return().
loop(Ref, TRef) ->
    receive
        {tick, Ref} ->
            io:format(user, "~s.~s", [?WHITE, ?RESET]),
            loop(Ref, TRef);
        {stop, Parent, Ref} when is_pid(Parent) ->
            io:format(user, "~n", []),
            _ =
                try
                    timer:cancel(TRef)
                catch
                    _:_ -> ok
                end,
            Parent ! Ref,
            exit(normal);
        Info ->
            io:format(user, "~n~s[~s] received unhandled message:~n~p~s~n", [?RED, ?MODULE, Info, ?RESET]),
            loop(Ref, TRef)
    end.

%% Arguments are deliberately unrestricted: these calls test runtime validation
%% of inputs that the public API's static contracts reject.
-spec assert_badarg(Module, Function, Arguments) -> Result when
    Module :: module(), Function :: atom(), Arguments :: [term()], Result :: ok.
assert_badarg(Module, Function, Arguments) ->
    try apply(Module, Function, Arguments) of
        Value -> ct:fail({expected_badarg, Module, Function, Arguments, Value})
    catch
        error:badarg -> ok;
        error:{badarg, _} -> ok;
        error:{badarg, _, _} -> ok
    end.

%% Keep deliberately invalid calls at the runtime assertion boundary.
-spec call(Module, Function, Arguments) -> Result when
    Module :: module(), Function :: atom(), Arguments :: [term()], Result :: term().
call(Module, Function, Arguments) -> apply(Module, Function, Arguments).

%% ct_run's counters omit failed end_per_suite/end_per_group callbacks.
%% Surefire records them as failure elements, even when its totals say zero.
-spec halt(Status) -> Result when Status :: non_neg_integer(), Result :: no_return().
halt(0) ->
    try
        {ok, [[LogDir]]} = init:get_argument(logdir),
        Report = filename:join(LogDir, "junit_report.xml"),
        {Document, _} = xmerl_scan:file(Report, [{quiet, true}]),
        case xmerl_xpath:string("//failure | //error", Document) of
            [] ->
                erlang:halt(0);
            Failures ->
                io:format(standard_error, "Common Test recorded ~B failures; see ~ts~n", [length(Failures), Report]),
                erlang:halt(1)
        end
    catch
        Class:Reason ->
            io:format(standard_error, "Cannot verify Common Test results: ~p:~tp~n", [Class, Reason]),
            erlang:halt(1)
    end;
halt(Status) ->
    erlang:halt(Status).
