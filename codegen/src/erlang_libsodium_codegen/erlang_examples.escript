#!/usr/bin/env escript
-mode(compile).

main([Ebin, Input, Output]) ->
    try
        true = code:add_patha(Ebin),
        {ok, _} = application:ensure_all_started(libsodium),
        {ok, Data} = file:read_file(Input),
        Requests = json:decode(Data),
        {Status, Result} = evaluate(Requests, 0, []),
        ok = file:write_file(Output, json:encode(Result)),
        halt(Status)
    catch
        Class:Reason:Stack ->
            Message = unicode:characters_to_binary(
                io_lib:format("~p:~tp~n~tp", [Class, Reason, Stack])
            ),
            ok = file:write_file(Output, json:encode(#{error => Message})),
            halt(1)
    end.

evaluate([], _, Results) ->
    {0, #{results => lists:reverse(Results)}};
evaluate([Request | Rest], Index, Results) ->
    try
        Source = string:trim(unicode:characters_to_list(maps:get(<<"source">>, Request))),
        Code =
            case lists:reverse(Source) of
                [$. | _] -> Source;
                _ -> Source ++ "."
            end,
        {ok, Tokens, _} = erl_scan:string(Code),
        {ok, Expressions} = erl_parse:parse_exprs(Tokens),
        {value, Value, _} = erl_eval:exprs(Expressions, erl_eval:new_bindings()),
        Formatted =
            case maps:get(<<"format">>, Request) of
                <<"check">> -> <<"ok">>;
                <<"hex">> when is_binary(Value) -> binary:encode_hex(Value);
                <<"text">> when is_binary(Value) -> Value;
                <<"term">> -> unicode:characters_to_binary(io_lib:format("~0tp", [Value]))
            end,
        evaluate(Rest, Index + 1, [Formatted | Results])
    catch
        Class:Reason:Stack ->
            Message = unicode:characters_to_binary(
                io_lib:format("~p:~tp~n~tp", [Class, Reason, Stack])
            ),
            {1, #{index => Index, error => Message}}
    end.
