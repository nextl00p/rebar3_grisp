-module(rebar3_grisp_deploy).

% Callbacks
-export([init/1]).
-export([do/1]).
-export([format_error/1]).

-include("rebar3_grisp.hrl").

-import(rebar3_grisp_util, [
    info/1,
    info/2,
    console/1,
    console/2,
    abort/1,
    abort/2,
    sh/1,
    set/3
]).

-define(BLOCKSIZE, 4194304). % 4MB

%--- Callbacks -----------------------------------------------------------------

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([
            {namespace, grisp},
            {name, deploy},
            {module, ?MODULE},
            {bare, true},
            {deps, [{default, install_deps}]},
            {example, "rebar3 grisp deploy"},
            {opts, [
                {relname, $n, "relname", string, "Specify the name for the release that will be deployed"},
                {relvsn, $v, "relvsn", string, "Specify the version of the release"},
                {destination, $d, "destination", string, "Path to put deployed release in"},
                {force, $f, "force", {boolean, false}, "Replace existing files"},
                {pre_script, undefined, "pre-script", string, "Shell script to run before deploying begins"},
                {post_script, undefined, "post-script", string, "Shell script to run after deploying has finished"}
            ]},
            {profiles, [grisp]},
            {short_desc, "Deploy a GRiSP release to a destination"},
            {desc,
"Deploys a GRiSP application.

The command requires the release name and version to be provided.
"
            }
    ]),
    {ok, rebar_state:add_provider(State, Provider)}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    info("~p", [Args]),
    Config = rebar_state:get(State, grisp, []),
    RelName = proplists:get_value(relname, Args),
    RelVsn = proplists:get_value(relvsn, Args),
    OTPVersion = rebar3_grisp_util:get([otp, version], Config,
        ?DEFAULT_OTP_VSN
    ),
    Board = rebar3_grisp_util:get([board], Config, ?DEFAULT_GRISP_BOARD),
    Version = rebar3_grisp_util:get([otp, version], Config, ?DEFAULT_OTP_VSN),

    case rebar3_grisp_util:toolchain_or_prebuilt(Config) of
        prebuilt ->
            info("Trying to obtain prebuilt OTP version"),
            Apps = rebar3_grisp_util:apps(State),
            Hash = hash_grisp_files(Apps, Board, "", Version),
            info("Trying to obtain OTP ~p ~p", [Version, Hash]),
            try obtain_prebuilt(Version, Hash)
            catch
                error:nomatch -> abort("We don't have that version of OTP in our download archive. " ++
                                           "Either you modified some of the C files of the grisp OTP " ++
                                           "application or you specified a wrong OTP version. " ++
                                           "Please build your own toolchain.")
            end,
            InstallRoot = rebar3_grisp_util:otp_install_root(OTPVersion, Hash, prebuilt);
        Dir when is_list(Dir) ->
            InstallRoot = rebar3_grisp_util:otp_install_root(State, OTPVersion, build)
    end,
    InstallRelVer = rebar3_grisp_util:otp_install_release_version(InstallRoot),
    check_otp_release(InstallRelVer),
    State3 = make_release(State, RelName, RelVsn, InstallRoot),
    Force = proplists:get_value(force, Args),
    Dest = get_option(destination, [deploy, destination], State),
    info("Deploying ~s-~s to ~s", [RelName, RelVsn, Dest]),
    run_script(pre_script, State),
                                                % FIXME: Resolve ERTS version
    ERTSPath = filelib:wildcard(filename:join(InstallRoot, "erts-*")),
    "erts-" ++ ERTSVsn = filename:basename(ERTSPath),
    copy_files(State3, RelName, RelVsn, Board, ERTSVsn, Dest, Force),
    copy_release(State3, RelName, RelVsn, Dest, Force),
    run_script(post_script, State),
    {ok, State3}.


-spec format_error(any()) ->  iolist().
format_error(Reason) ->
    io_lib:format("~p", [Reason]).

%--- Internal ------------------------------------------------------------------

check_otp_release(InstallRelVer) ->
    case {InstallRelVer, erlang:system_info(otp_release)} of
        {Target, Target} -> ok;
        {Target, Current} ->
            rebar_api:warn(
                "Current Erlang version (~p) does not match target "
                "Erlang version (~p). It is not guaranteed that the "
                "deployed release will work!", [Current, Target]
            )
    end.

make_release(_State, Name, Version, _InstallRoot) when
  Name == undefined; Version == undefined ->
    rebar_api:abort("Release name and/or version not specified", []);
make_release(State, Name, Version, InstallRoot) ->
    State2 = rebar_state:set(State, relx, [
        {include_erts, InstallRoot},
        {system_libs, InstallRoot},
        {extended_start_script, false},
        {dev_mode, false}
        |rebar_state:get(State, relx, [])
    ]),
    {ok, State3} = rebar_prv_do:do_tasks(
        [{"release", ["-n", Name, "-v", Version]}],
        rebar_state:namespace(State2, default)
    ),
    rebar_state:namespace(State3, grisp).

run_script(Name, State) ->
    case get_option(Name, [deploy, Name], State, undefined) of
        undefined -> ok;
        Script ->
            console("* Running ~p", [Name]),
            {ok, Output} = sh(Script),
            case trim(Output) of
                ""      -> ok;
                Trimmed -> console(Trimmed)
            end
    end.

copy_files(State, RelName, RelVsn, Board, ERTSVsn, Dest, Force) ->
    console("* Copying files..."),
    Tree = build_from_to_tree(State, Board, "files"),
    Context = [
        {release_name, RelName},
        {release_version, RelVsn},
        {erts_vsn, ERTSVsn}
    ],
    maps:map(
        fun(Target, Source) ->
            write_file(Dest, Target, Source, Force, Context)
        end,
        Tree
    ).

grisp_files(Dir, Board, Subdir) ->
    Path = filename:join([Dir, "grisp", Board, Subdir]),
    resolve_files(find_files(Path), Path).

write_file(Dest, Target, Source, Force, Context) ->
    Path = filename:join(Dest, Target),
    rebar_api:debug("Creating ~p from ~p", [Path, Source]),
    Content = load_file(Source, Context),
    force_execute(Path, Force,
        fun(F) ->
            ensure_dir(F),
            ok = file:write_file(F, Content)
        end
    ).

find_files(Dir) ->
    [F || F <- filelib:wildcard(Dir ++ "/**"), filelib:is_regular(F)].

resolve_files(Files, Root) -> resolve_files(Files, Root, #{}).

resolve_files([File|Files], Root, Resolved) ->
    Relative = prefix(File, Root ++ "/"),
    Name = filename:rootname(Relative, ".mustache"),
    resolve_files(Files, Root, maps:put(
                                 Name,
                                 resolve_file(Root, Relative, Name, maps:find(Name, Resolved)),
                                 Resolved
                                ));
resolve_files([], _Root, Resolved) ->
    Resolved.

prefix(String, Prefix) ->
    case lists:split(length(Prefix), String) of
        {Prefix, Rest} -> Rest;
        _              -> String
    end.

resolve_file(Root, Source, Source, error) ->
    filename:join(Root, Source);
resolve_file(Root, Source, _Target, _) ->
    {template, filename:join(Root, Source)}.

load_file({template, Source}, Context) ->
    Parsed = bbmustache:parse_file(Source),
    bbmustache:compile(Parsed, Context, [{key_type, atom}]);
load_file(Source, _Context) ->
    {ok, Binary} = file:read_file(Source),
    Binary.

copy_release(State, Name, _Version, Dest, Force) ->
    console("* Copying release..."),
    Source = filename:join([rebar_dir:base_dir(State), "rel", Name]),
    Target = filename:join(Dest, Name),
    Command = case Force of
        true  -> "cp -Rf";
        false -> "cp -R"
    end,
    ensure_dir(Target),
    sh(string:join([Command, Source ++ "/", Target], " ")).

force_execute(File, Force, Fun) ->
    case {filelib:is_file(File), Force} of
        {true, false} ->
            abort(
                "Destination ~s already exists (use --force to overwrite)",
                [File]
            );
        _ ->
            ok
    end,
    Fun(File).

ensure_dir(File) ->
    case filelib:ensure_dir(File) of
        ok    -> ok;
        Error -> abort("Could not create target directory: ~p", [Error])
    end.

get_option(Arg, ConfigKey, State) ->
    get_arg_option(Arg, State, fun(Config) ->
        rebar3_grisp_util:get(ConfigKey, Config)
    end).

get_option(Arg, ConfigKey, State, Default) ->
    get_arg_option(Arg, State, fun(Config) ->
        rebar3_grisp_util:get(ConfigKey, Config, Default)
    end).

get_arg_option(Arg, State, Fun) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    Config = rebar_state:get(State, grisp, []),
    case proplists:get_value(Arg, Args) of
        undefined -> Fun(Config);
        Value     -> Value
    end.

trim(String) ->
    re:replace(String, "(^[\s\n\t]+|[\s\n\t]+$)", "", [global, {return, list}]).


obtain_prebuilt(Version, ExpectedHash) ->
    Tarball = rebar3_grisp_util:otp_cache_file(Version, ExpectedHash),
    case filelib:is_regular(Tarball) of
        true ->
            ETag = get_etag(Tarball),
            download_and_unpack(Version, ExpectedHash, ETag);
        false ->
            download_and_unpack(Version, ExpectedHash, "NULL")
    end.

get_etag(Tarball) ->
    case hash_file(Tarball, md5) of
        {ok, Hash} -> Hash;
        {error, enoent} -> not_found
    end.

download_and_unpack(Version, Hash, ETag) ->
    case file:delete(rebar3_grisp_util:otp_cache_file_temp(Version, Hash)) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, FileReason} -> abort("Error ~p", [FileReason])
    end,
    ssl:start(),
    {ok, InetsPid} = inets:start(httpc, [{profile, rebar3_grisp}], stand_alone),
    HTTPOptions = [{connect_timeout, 5000}],
    Options = [{stream, rebar3_grisp_util:otp_cache_file_temp(Version, Hash)}, {body_format, binary}],
    Url = ?DOWNLOAD_CDN_URI ++ rebar3_grisp_util:otp_cache_file_name(Version, Hash),
    Headers = [{"If-None-Match", ETag}],
    Response = httpc:request(get, {Url, Headers}, HTTPOptions, Options, InetsPid),
    case Response of
        {ok, {{_HTTPVersion, 304, "Not Modified"}, _OtherHeaders}} -> ok;
        {ok, saved_to_file} -> move_file(rebar3_grisp_util:otp_cache_file_temp(Version, Hash), rebar3_grisp_util:otp_cache_file(Version, Hash));
        {ok, {{_HTTPVersion, 404, "Not Found"}, _, _}} -> console("Got  HTTP/1.1 404 Not Found. We don't have an archive for you yet");
        {ok, Other} -> console("Unexpected HTTP reply: ~p, Trying to use cached file~n", [Other]);
        {error, ResponseReason} -> console("HTTP or Network error. Trying to use local cache: ~p~n", [ResponseReason])
    end,
    case filelib:is_regular(rebar3_grisp_util:otp_cache_file(Version, Hash)) of
        true -> maybe_unpack(Version, Hash);
        false -> abort("Could not obtain prebuilt OTP for your configuration. " ++
                           "This means either you are not connected to the internet, "++
                           "there is something wrong with our CDN, or you have modified "++
                           "any of the C drivers. In any case please build your own toolchain" ++
                           "and OTP (using rebar3 grisp build), or try later.")
    end.

move_file(From, To) ->
    case file:delete(To) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} -> abort("Error ~p", [Reason])
    end,
    file:rename(From, To),
    file:delete(From).

maybe_unpack(Version, Hash) ->
    case should_unpack(Version, Hash) of
        yes -> tar:extract(rebar3_grisp_util:otp_cache_file(Version, Hash), [{compressed}, {cwd, rebar3_grisp_util:otp_install_root(Version, Hash, prebuilt)}]);
        no -> ok
    end.

should_unpack(Version, Hash) ->
    DirModificationDate = filelib:last_modified(rebar3_grisp_util:otp_install_root(Version, Hash, prebuilt)),
    FileModificationDate = filelib:last_modified(rebar3_grisp_util:otp_cache_file(Version, Hash)),
    case {FileModificationDate, DirModificationDate} of
        {_, 0} -> yes;
        {X, X} -> no;
        _Mismatch -> yes
    end.

hash_grisp_files(Apps, Board, OTPRoot, Version) ->
    {SystemFiles, DriverFiles} = rebar3_grisp_util:get_copy_list(Apps, Board, OTPRoot, Version),
    ToFrom = maps:merge(SystemFiles, DriverFiles),
    rebar_api:debug("Hashing ToFrom map: ~p", [ToFrom]),

%% WRONG!!!:
    %Tree = build_from_to_tree(State, Board, {"sys", "drivers"}),

                                                % not needed:

    %Relative = make_relative(maps:to_list(ToFrom), rebar_app_info:dir(App)),

    Sorted = lists:keysort(1, maps:to_list(ToFrom)),
    FileHashes = lists:map(
                   fun({Target, Source}) ->
                           rebar_api:debug("Hashing ~p for location ~p", [Source, Target]),
                           hash_file(Source, sha256, Target)
                   end,
                   Sorted
                  ),
    HashString = hashes_to_string(FileHashes),
    %%TODO: write to file
    lists:flatten(format_sha256(crypto:hash(sha256, HashString))).

hashes_to_string(Hashes) ->
    lists:map(
      fun({Target, Hash}) ->
              io_lib:format("~s ~s~n", [Target, format_sha256(Hash)]) end,
      Hashes).

format_sha256(Hash) when is_binary(Hash) ->
    <<Int:256/big-unsigned-integer>> = Hash,
    format_sha256(Int);
format_sha256(Int) when is_integer(Int) ->
    io_lib:format("~.16B", [Int]).

hash_file_read(FileHandle, HashHandle) ->
    case file:read(FileHandle, ?BLOCKSIZE) of
        {ok, Bin} -> hash_file_read(FileHandle, crypto:hash_update(HashHandle, Bin));
        eof ->
            file:close(FileHandle),
            {ok, crypto:hash_final(HashHandle)}
    end.

hash_file(File, Algorithm, Name) ->
    CryptoHandle = crypto:hash_init(Algorithm),
    HashHandle = crypto:hash_update(CryptoHandle, list_to_binary(Name)),
    case file:open(File, [binary, raw, read]) of
        {ok, FileHandle} -> hash_file_read(FileHandle, HashHandle);
        Error -> Error
    end.

hash_file(File, Algorithm) ->
    hash_file(File, Algorithm, "").

make_relative(TargetsSources, Root) ->
    lists:map(fun({Target, Source}) ->
                      {_Abs, Rel} = lists:split(length(Root), filename:split(Target)),
                      {Rel, Source}
              end,
              TargetsSources).

% Builds a map From => To, project's files replace grisp files,
build_from_to_tree(State, Board, Subdir) ->
    AllApps = rebar_state:all_deps(State) ++ rebar_state:project_apps(State),
    case rebar3_grisp_util:grisp_app(AllApps) of
        {[], _} -> grisp_files(rebar_state:dir(State), Board, Subdir);
        {[Grisp], _} ->
            [GrispFiles, ProjectFiles] = lists:map(
                                           fun(Dir) -> grisp_files(Dir, Board, Subdir) end,
                                           [rebar_app_info:dir(Grisp), rebar_state:dir(State)]
                                          ),
            maps:merge(GrispFiles, ProjectFiles)
    end.
