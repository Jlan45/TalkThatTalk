use std::collections::{BTreeMap, HashMap, VecDeque};

use bytes::Bytes;
use serde_json::{Value, json};
use ttt_core::RequestId;

use crate::openai_anthropic::map_openai_finish_reason;
use crate::sse::sse_event_bytes;

#[derive(Default)]
struct ToolCall {
    id: String,
    name: String,
    arguments: String,
}

pub struct AnthropicStream {
    model: String,
    id: String,
    started: bool,
    pub(crate) finished: bool,
    pub(crate) finish_reason: Option<&'static str>,
    text_index: Option<usize>,
    next_index: usize,
    tools: BTreeMap<u64, ToolCall>,
    item_indexes: HashMap<String, u64>,
    input_tokens: Option<u64>,
    output_tokens: u64,
    cached_tokens: Option<u64>,
}

impl AnthropicStream {
    pub(crate) fn new(model: String) -> Self {
        Self {
            model,
            id: format!("msg_ttt_{}", RequestId::next().0),
            started: false,
            finished: false,
            finish_reason: None,
            text_index: None,
            next_index: 0,
            tools: BTreeMap::new(),
            item_indexes: HashMap::new(),
            input_tokens: None,
            output_tokens: 0,
            cached_tokens: None,
        }
    }

    pub(crate) fn openai_chunk(&mut self, value: &Value, out: &mut VecDeque<Bytes>) {
        self.set_metadata(value);
        self.read_usage(&value["usage"]);
        let choice = &value["choices"][0];
        let delta = &choice["delta"];
        if let Some(text) = delta["content"].as_str().filter(|text| !text.is_empty()) {
            self.text(text, out);
        }
        for call in delta["tool_calls"].as_array().into_iter().flatten() {
            let Some(index) = call["index"].as_u64() else {
                self.fail("Upstream tool call is missing its index", out);
                return;
            };
            let tool = self.tools.entry(index).or_default();
            if let Some(id) = call["id"].as_str().filter(|id| !id.is_empty()) {
                tool.id = id.to_owned();
            }
            if let Some(name) = call["function"]["name"].as_str() {
                tool.name.push_str(name);
            }
            if let Some(args) = call["function"]["arguments"].as_str() {
                tool.arguments.push_str(args);
            }
        }
        if let Some(reason) = choice["finish_reason"].as_str() {
            self.finish_reason = Some(map_openai_finish_reason(Some(reason)));
        }
    }

    pub(crate) fn responses_event(
        &mut self,
        event: &str,
        value: &Value,
        out: &mut VecDeque<Bytes>,
    ) {
        match event {
            "response.created" => self.set_metadata(&value["response"]),
            "response.output_text.delta" | "response.refusal.delta" => {
                if let Some(text) = value["delta"].as_str().filter(|text| !text.is_empty()) {
                    self.text(text, out);
                }
            }
            "response.output_item.added" | "response.output_item.done" => {
                if value["item"]["type"] == "function_call"
                    && let Some(index) = self.item_index(value)
                {
                    self.record_response_tool(index, &value["item"]);
                }
            }
            "response.function_call_arguments.delta" | "response.function_call_arguments.done" => {
                let Some(index) = self.item_index(value) else {
                    self.fail("Upstream tool arguments are missing their item index", out);
                    return;
                };
                let tool = self.tools.entry(index).or_default();
                if let Some(args) = value["arguments"].as_str() {
                    tool.arguments = args.to_owned();
                } else if let Some(delta) = value["delta"].as_str() {
                    tool.arguments.push_str(delta);
                }
            }
            "response.completed" | "response.incomplete" => {
                let response = &value["response"];
                self.set_metadata(response);
                self.read_usage(&response["usage"]);
                for (index, item) in response["output"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    if item["type"] == "function_call" {
                        self.record_response_tool(index as u64, item);
                    }
                }
                self.finish_reason = match event {
                    "response.completed" => Some("end_turn"),
                    _ => match response["incomplete_details"]["reason"].as_str() {
                        Some("max_output_tokens") => Some("max_tokens"),
                        Some("content_filter") => Some("refusal"),
                        _ => None,
                    },
                };
                self.finish(out);
            }
            _ => {}
        }
    }

    fn item_index(&self, value: &Value) -> Option<u64> {
        value["output_index"].as_u64().or_else(|| {
            let id = value["item_id"]
                .as_str()
                .or_else(|| value["item"]["id"].as_str())?;
            self.item_indexes.get(id).copied()
        })
    }

    fn record_response_tool(&mut self, index: u64, item: &Value) {
        if let Some(id) = item["id"].as_str() {
            self.item_indexes.insert(id.to_owned(), index);
        }
        let tool = self.tools.entry(index).or_default();
        if let Some(id) = item["call_id"].as_str() {
            tool.id = id.to_owned();
        }
        if let Some(name) = item["name"].as_str() {
            tool.name = name.to_owned();
        }
        if let Some(args) = item["arguments"].as_str().filter(|args| !args.is_empty()) {
            tool.arguments = args.to_owned();
        }
    }

    fn set_metadata(&mut self, value: &Value) {
        if self.started {
            return;
        }
        if let Some(id) = value["id"].as_str().filter(|id| !id.is_empty()) {
            self.id = id.to_owned();
        }
    }

    fn read_usage(&mut self, usage: &Value) {
        self.input_tokens = usage["input_tokens"]
            .as_u64()
            .or_else(|| usage["prompt_tokens"].as_u64())
            .or(self.input_tokens);
        self.output_tokens = usage["output_tokens"]
            .as_u64()
            .or_else(|| usage["completion_tokens"].as_u64())
            .unwrap_or(self.output_tokens);
        self.cached_tokens = usage
            .pointer("/input_tokens_details/cached_tokens")
            .and_then(Value::as_u64)
            .or_else(|| {
                usage
                    .pointer("/prompt_tokens_details/cached_tokens")
                    .and_then(Value::as_u64)
            })
            .or(self.cached_tokens);
    }

    fn usage(&self, output_tokens: u64) -> Value {
        let mut usage = json!({"output_tokens": output_tokens});
        if let Some(input) = self.input_tokens {
            usage["input_tokens"] = json!(input.saturating_sub(self.cached_tokens.unwrap_or(0)));
        }
        if let Some(cached) = self.cached_tokens {
            usage["cache_read_input_tokens"] = json!(cached);
        }
        usage
    }

    fn start(&mut self, out: &mut VecDeque<Bytes>) {
        if self.started {
            return;
        }
        self.started = true;
        let mut usage = self.usage(0);
        if usage.get("input_tokens").is_none() {
            usage["input_tokens"] = json!(0);
        }
        out.push_back(sse_event_bytes(
            "message_start",
            &json!({
                "type": "message_start", "message": {
                    "id": self.id, "type": "message", "role": "assistant", "model": self.model,
                    "content": [], "stop_reason": null, "stop_sequence": null, "usage": usage,
                },
            }),
        ));
    }

    fn start_block(&mut self, block: Value, out: &mut VecDeque<Bytes>) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        out.push_back(sse_event_bytes(
            "content_block_start",
            &json!({
                "type": "content_block_start", "index": index, "content_block": block,
            }),
        ));
        index
    }

    fn text(&mut self, text: &str, out: &mut VecDeque<Bytes>) {
        self.start(out);
        let index = self
            .text_index
            .unwrap_or_else(|| self.start_block(json!({"type": "text", "text": ""}), out));
        self.text_index = Some(index);
        out.push_back(sse_event_bytes("content_block_delta", &json!({
            "type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text},
        })));
    }

    pub(crate) fn finish(&mut self, out: &mut VecDeque<Bytes>) {
        let Some(mut reason) = self.finish_reason else {
            self.fail("Upstream stream ended without a completion event", out);
            return;
        };
        if reason == "tool_use" && self.tools.is_empty()
            || self.tools.values().any(|tool| {
                tool.id.is_empty()
                    || tool.name.is_empty()
                    || !tool.arguments.trim().is_empty()
                        && serde_json::from_str::<serde_json::Map<String, Value>>(&tool.arguments)
                            .is_err()
            })
        {
            self.fail("Upstream returned an incomplete function call", out);
            return;
        }
        self.start(out);
        if let Some(index) = self.text_index.take() {
            stop_block(index, out);
        }
        if !self.tools.is_empty() && reason == "end_turn" {
            reason = "tool_use";
        }
        for tool in std::mem::take(&mut self.tools).into_values() {
            let index = self.start_block(
                json!({"type": "tool_use", "id": tool.id, "name": tool.name, "input": {}}),
                out,
            );
            let args = if tool.arguments.trim().is_empty() {
                "{}"
            } else {
                &tool.arguments
            };
            out.push_back(sse_event_bytes(
                "content_block_delta",
                &json!({
                    "type": "content_block_delta", "index": index,
                    "delta": {"type": "input_json_delta", "partial_json": args},
                }),
            ));
            stop_block(index, out);
        }
        self.finished = true;
        out.push_back(sse_event_bytes(
            "message_delta",
            &json!({
                "type": "message_delta", "delta": {"stop_reason": reason, "stop_sequence": null},
                "usage": self.usage(self.output_tokens),
            }),
        ));
        out.push_back(sse_event_bytes(
            "message_stop",
            &json!({"type": "message_stop"}),
        ));
    }

    pub(crate) fn fail(&mut self, message: &str, out: &mut VecDeque<Bytes>) {
        self.finished = true;
        out.push_back(sse_event_bytes(
            "error",
            &json!({
                "type": "error", "error": {"type": "api_error", "message": message},
            }),
        ));
    }
}

fn stop_block(index: usize, out: &mut VecDeque<Bytes>) {
    out.push_back(sse_event_bytes(
        "content_block_stop",
        &json!({"type": "content_block_stop", "index": index}),
    ));
}
