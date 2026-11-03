use super::*;
use std::cell::Cell;

fn arguments(name: &str) -> serde_json::Value {
    if name == "memory_diary_search" {
        serde_json::json!({"query":"synthetic query"})
    } else {
        serde_json::json!({"source_id":"synthetic","fragment_id":"synthetic"})
    }
}

#[test]
fn diary_tools_schema_arguments_and_strict_bounds() -> Result<(), String> {
    let schemas = tools();
    let search = &schemas
        .iter()
        .find(|t| t.0 == "memory_diary_search")
        .ok_or("search schema")?
        .2;
    let read = &schemas
        .iter()
        .find(|t| t.0 == "memory_diary_fragment")
        .ok_or("read schema")?
        .2;
    assert_eq!(search["properties"]["query"]["maxLength"], 500);
    assert_eq!(search["properties"]["max_chars"]["minimum"], 512);
    assert_eq!(read["properties"]["neighbors"]["maximum"], 1);
    assert_eq!(search["additionalProperties"], false);
    assert_eq!(read["additionalProperties"], false);
    let argv = tool_argv(
        "memory_diary_search",
        &serde_json::json!({"query":"--mode=lexical","mode":"hybrid","limit":5,"max_chars":4000}),
    )?;
    assert_eq!(
        argv,
        [
            "diary-search",
            "--limit",
            "5",
            "--max-chars",
            "4000",
            "--mode",
            "hybrid",
            "--",
            "--mode=lexical"
        ]
    );
    let argv = tool_argv(
        "memory_diary_fragment",
        &serde_json::json!({"source_id":"s","fragment_id":"f","neighbors":1,"max_chars":512}),
    )?;
    assert_eq!(
        argv,
        [
            "diary-fragment",
            "--neighbors",
            "1",
            "--max-chars",
            "512",
            "--",
            "s",
            "f"
        ]
    );
    for name in ["memory_diary_search", "memory_diary_fragment"] {
        for (key, value) in [
            ("max_chars", serde_json::json!(511)),
            ("max_chars", serde_json::json!(12001)),
            ("max_chars", serde_json::json!("4000")),
            ("max_chars", serde_json::json!(true)),
            ("unknown", serde_json::json!(1)),
        ] {
            let mut args = arguments(name);
            args[key] = value;
            assert!(tool_argv(name, &args).is_err(), "invalid {name}/{key}");
        }
    }
    for value in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(21),
        serde_json::json!(1.5),
    ] {
        assert!(tool_argv(
            "memory_diary_search",
            &serde_json::json!({"query":"q","limit":value})
        )
        .is_err());
    }
    for query in [" ".to_owned(), "\u{4e2d}".repeat(501)] {
        assert!(tool_argv("memory_diary_search", &serde_json::json!({"query":query})).is_err());
    }
    assert!(tool_argv(
        "memory_diary_search",
        &serde_json::json!({"query":"\u{4e2d}".repeat(500)})
    )
    .is_ok());
    assert!(tool_argv(
        "memory_diary_search",
        &serde_json::json!({"query":"q","mode":"invalid"})
    )
    .is_err());
    assert!(tool_argv(
        "memory_diary_fragment",
        &serde_json::json!({"source_id":"s","fragment_id":"f","neighbors":2})
    )
    .is_err());
    Ok(())
}

#[test]
fn diary_tools_list_and_execution_agree_in_normal_readonly_off_and_deny() -> Result<(), String> {
    for name in ["memory_diary_search", "memory_diary_fragment"] {
        for access in [
            ServiceAccess::default(),
            ServiceAccess {
                readonly: true,
                off: false,
            },
            ServiceAccess {
                readonly: false,
                off: true,
            },
        ] {
            for deny in [None, Some(name)] {
                let policy = ToolPolicy::parse(None, deny)?;
                let calls = Cell::new(0);
                let invoke = |args: Vec<String>| {
                    calls.set(calls.get() + 1);
                    Ok(
                        serde_json::json!({"command":args[0],"status":"ok","summary":{},"items":[],"actions":[],"errors":[],"details":{}}),
                    )
                };
                let listed = tools_list_result(&policy, access);
                let visible = listed["tools"]
                    .as_array()
                    .ok_or("tools")?
                    .iter()
                    .any(|tool| tool["name"] == name);
                let expected = !access.off && deny.is_none();
                assert_eq!(visible, expected);
                let request = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments(name)}});
                let response =
                    handle_rpc_with(&request, &invoke, &policy, access).ok_or("response")?;
                assert_eq!(response["result"]["isError"], !expected);
                assert_eq!(calls.get(), usize::from(expected));
            }
        }
    }
    Ok(())
}

#[test]
fn diary_tool_http_and_sse_enforce_deny_before_callbacks() -> Result<(), String> {
    for name in ["memory_diary_search", "memory_diary_fragment"] {
        for (path, accept) in [("/mcp", "application/json"), ("/sse", "text/event-stream")] {
            let policy = ToolPolicy::parse(None, Some(name))?;
            let dispatch = |request: &serde_json::Value| {
                handle_rpc_with(
                    request,
                    &|_| panic!("denied diary callback"),
                    &policy,
                    ServiceAccess::default(),
                )
            };
            let (status,content_type,body)=http_response_with(HttpIn{method:"POST".into(),path:path.into(),origin:"http://127.0.0.1".into(),accept:accept.into(),body:serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments(name)}}).to_string()},&dispatch);
            assert_eq!(status, 200);
            let text = String::from_utf8(body).map_err(|e| e.to_string())?;
            let json = if content_type.starts_with("text/event-stream") {
                text.lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .ok_or("SSE data")?
            } else {
                &text
            };
            let response: serde_json::Value =
                serde_json::from_str(json).map_err(|e| e.to_string())?;
            assert_eq!(response["result"]["isError"], true);
        }
    }
    Ok(())
}
