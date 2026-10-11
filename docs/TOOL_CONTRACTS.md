# Agent Tool Contracts

## search_logs
Input: user, host, start_time, end_time, optional filters.
Output: matching evidence records, count, query metadata, explicit error state.

## get_related_events
Input: host, center timestamp, time radius.
Output: ordered related events with source metadata.

## search_knowledge_base
Input: query, top_k, optional source filters.
Output: chunks with chunk_id, title, source URI/path, type, version/date when available, relevance metadata.
No-result is a valid state.

## lookup_attack_technique
Input: verified technique ID or behavior query.
Output: verified technique ID, name, description, source/version metadata.
Unknown IDs must not be invented.

## State requirements
Preserve investigation ID, tool name, input, output/error and timestamp.
Tool results must be distinguishable from LLM-generated text.
