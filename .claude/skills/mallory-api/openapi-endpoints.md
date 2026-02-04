## OpenAPI Endpoints

Endpoints are grouped by path and method. Query parameters listed below are filter/constraint inputs for each endpoint, including allowed values (enum/pattern) when provided by the API.

### `/api-keys`
- `GET`: Get Api Keys Route
- `POST`: Create Api Key Route

### `/api-keys/{api_key_uuid}`
- `DELETE`: Delete Api Key Route

### `/v1`
- `GET`: Welcome

### `/v1/actors`
- `GET`: Threat Actors Index
  Filters/params:
  - `filter` (string, optional) A string used to filter threat actors. It can start with specific prefixes to indicate the type of filter:
- `name:`: Filter by Name, case-insensitive.
- `uuid:`: Filter by UUID, case-insensitive.
- `internal_name:`: Filter by internal_name (exact match).
- `desc:`: Filter by description (searches both description and gen_description fields).
If no prefix is provided, it defaults to filtering on the display_name or name fields.
Examples:
- `name:APT`
- `name:lazarus_group`
- `internal_name:m-threat-actor-happy-yellow-dog-a123`
- `lazarus_group`
- `Lazarus Group`
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `sort` (string, optional) Field to sort by - either name, created_at, updated_at, enriched_at, trending_1d, trending_7d, or trending_30d (pattern: ^(name|created_at|updated_at|enriched_at|trending_1d|trending_7d|trending_30d)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `include_merged` (boolean, optional) Include entities that have been merged into other entities (default: False)
  - `followed` (boolean, optional) When true, returns only threat actors that the tenant is following (default: False)
  - `motivation` (string | null, optional) Filter on the motivation field by exact match
  - `motivation__neq` (string | null, optional) Filter on the motivation field for items not equal to the given value
  - `motivation__in` (string | null, optional) Filter on the motivation field for items that match any value in a comma-separated list
  - `motivation__not_in` (string | null, optional) Filter on the motivation field for items that do not match any value in a comma-separated list
  - `motivation__like` (string | null, optional) Filter on the motivation field for items that match a SQL LIKE pattern (use % as wildcard, case-sensitive)
  - `motivation__ilike` (string | null, optional) Filter on the motivation field for items that match a SQL LIKE pattern (use % as wildcard, case-insensitive)
  - `sponsor` (string | null, optional) Filter on the sponsor field by exact match
  - `sponsor__neq` (string | null, optional) Filter on the sponsor field for items not equal to the given value
  - `sponsor__in` (string | null, optional) Filter on the sponsor field for items that match any value in a comma-separated list
  - `sponsor__not_in` (string | null, optional) Filter on the sponsor field for items that do not match any value in a comma-separated list
  - `sponsor__like` (string | null, optional) Filter on the sponsor field for items that match a SQL LIKE pattern (use % as wildcard, case-sensitive)
  - `sponsor__ilike` (string | null, optional) Filter on the sponsor field for items that match a SQL LIKE pattern (use % as wildcard, case-insensitive)
  - `family_name` (string | null, optional) Filter on the family_name field by exact match
  - `family_name__neq` (string | null, optional) Filter on the family_name field for items not equal to the given value
  - `family_name__in` (string | null, optional) Filter on the family_name field for items that match any value in a comma-separated list
  - `family_name__not_in` (string | null, optional) Filter on the family_name field for items that do not match any value in a comma-separated list
  - `family_name__like` (string | null, optional) Filter on the family_name field for items that match a SQL LIKE pattern (use % as wildcard, case-sensitive)
  - `family_name__ilike` (string | null, optional) Filter on the family_name field for items that match a SQL LIKE pattern (use % as wildcard, case-insensitive)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/actors/trending/diff`
- `GET`: Trending Diff Endpoint
  Filters/params:
  - `window` (string, optional) Time window for comparison. Format: '<number><unit>' where unit is 'd' (days) or 'h' (hours). Examples: '1d', '12h', '7d'. Maximum: 30d or 720h. Default: '1d'. (pattern: ^\d+[dh]$; default: 1d)
  - `trending_limit` (integer, optional) Maximum number of entities to consider as 'trending' per period. Only the top N entities by mention count are compared. Default: 10. (min: 1; max: 100; default: 10)

### `/v1/actors/{identifier}`
- `GET`: Lookup Threat Actor

### `/v1/actors/{identifier}/attack_patterns`
- `GET`: Single Threat Actor Attack Patterns
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|mitre_attack_id|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/actors/{identifier}/enrich`
- `POST`: Enrich Threat Actor

### `/v1/actors/{identifier}/export`
- `GET`: Export Threat Actor
  Filters/params:
  - `relationships_created_after` (string | null, optional) Filter related objects to only include those created after this ISO8601/RFC3339 timestamp
  - `relationships_created_before` (string | null, optional) Filter related objects to only include those created before this ISO8601/RFC3339 timestamp

### `/v1/actors/{identifier}/mentions`
- `GET`: Single Threat Actor Mentions
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|published_at|source)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'user_generated_content:true' or 'user_generated_content:false')

### `/v1/actors/{identifier}/observables`
- `GET`: Single Threat Actor Observables
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(type|name|created_at|published_at)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'type:ip.v4', 'type:domain', 'type:hash.sha256')

### `/v1/admin`
- `GET`: Index

### `/v1/admin/alias_claims`
- `GET`: List Alias Claims
  Filters/params:
  - `entity_type` (string | null, optional) Filter by entity type
  - `source_slug` (string | null, optional) Filter by source slug
  - `entity_uuid` (string | null, optional) Filter by entity UUID
  - `resolved` (boolean | null, optional) Filter by resolution status
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)

### `/v1/admin/alias_claims/analytics/entity_claims/{entity_uuid}`
- `GET`: Get Entity Claims Endpoint
  Filters/params:
  - `entity_type` (string, required) Entity type

### `/v1/admin/alias_claims/analytics/high_confidence_pairs`
- `GET`: Get High Confidence Pairs Endpoint
  Filters/params:
  - `entity_type` (string, required) Entity type to analyze
  - `min_sources` (integer, optional) Minimum number of sources required (min: 2; default: 2)

### `/v1/admin/alias_claims/analytics/merge_candidates`
- `GET`: Get Merge Candidates Endpoint
  Filters/params:
  - `entity_type` (string, required) Entity type to analyze
  - `min_sources` (integer, optional) Minimum number of sources required (min: 2; default: 3)
  - `limit` (integer, optional) Maximum number of candidates to return (min: 1; max: 500; default: 100)

### `/v1/admin/alias_claims/analytics/resolution_history`
- `GET`: Get Resolution History Endpoint
  Filters/params:
  - `external_name` (string, required) External name to lookup
  - `entity_type` (string, required) Entity type

### `/v1/admin/alias_claims/merge`
- `GET`: Merge Entities Get
  Filters/params:
  - `entity_type` (string, required) Type of entity to merge (e.g., threat_actor, malware, etc.)
  - `from` (string, required) Name to merge FROM (will be merged away)
  - `to` (string, required) Name to merge TO (this entity survives)
  - `merge_on` (string, optional) Field to match on: 'internal_name' (default) or 'external_name' (default: internal_name)
  - `reason` (string, required) Reason for the merge (for audit trail)
- `POST`: Merge Entities

### `/v1/admin/alias_claims/reject`
- `GET`: Reject Claim Pair Get
  Filters/params:
  - `entity_type` (string, required) Type of entity (e.g., 'threat_actor', 'malware')
  - `entity_1` (string, required) First external name in the pair
  - `entity_2` (string, required) Second external name in the pair
  - `reason` (string, required) Reason for rejection (helps train merge suggestion AI)
- `POST`: Reject Claim Pair

### `/v1/admin/alias_claims/rejected`
- `GET`: Get Rejected Claims Endpoint
  Filters/params:
  - `entity_type` (string | null, optional) Filter by entity type (e.g., 'threat_actor', 'malware')
  - `limit` (integer, optional) Maximum number of rejected pairs to return (min: 1; max: 500; default: 100)

### `/v1/admin/alias_claims/split`
- `POST`: Split Entities

### `/v1/admin/alias_claims/unmerge`
- `GET`: Unmerge Entities Get
  Filters/params:
  - `entity_type` (string, required) Type of entity to unmerge (e.g., threat_actor, malware, etc.)
  - `from` (string, required) External name of entity that was merged away (to restore)
- `POST`: Unmerge Entities

### `/v1/admin/alias_claims/{claim_uuid}`
- `GET`: Get Alias Claim

### `/v1/admin/aliases`
- `GET`: List Aliases
  Filters/params:
  - `filter` (string | null, optional) Filter term to filter aliases
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
- `POST`: Create Alias

### `/v1/admin/aliases/{alias_uuid}`
- `DELETE`: Delete Alias
- `GET`: Get Alias
- `PATCH`: Update Alias

### `/v1/admin/citations`
- `GET`: List Citations
  Filters/params:
  - `relation` (string | null, optional) Filter by relation type (e.g., 'cites', 'references')
  - `cited_url` (string | null, optional) Filter by cited URL (substring match)
  - `pending_only` (boolean, optional) Only show citations where cited_url is not yet a reference (alias for exclude_existing_references) (default: False)
  - `exclude_existing_references` (boolean, optional) Exclude citations where the cited URL already exists as a reference in the system (default: False)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)

### `/v1/admin/citations/analytics/summary`
- `GET`: Get Citations Summary

### `/v1/admin/citations/{uuid}`
- `DELETE`: Delete Citation
- `GET`: Get Citation

### `/v1/admin/citations/{uuid}/ingest`
- `POST`: Ingest Citation

### `/v1/admin/delta_tables`
- `GET`: Get Delta Tables

### `/v1/admin/delta_tables/{name}`
- `DELETE`: Delete Delta Table
  Filters/params:
  - `commit` (boolean, optional) Whether to commit the action to the database. (default: False)
- `GET`: Get Delta Table

### `/v1/admin/entities/{entity_type}/{entity_uuid}`
- `GET`: Get Entity
- `PATCH`: Update Entity

### `/v1/admin/entities/{entity_type}/{entity_uuid}/aliases`
- `GET`: Get Entity Aliases

### `/v1/admin/entities/{entity_type}/{entity_uuid}/enrich`
- `POST`: Enrich Entity

### `/v1/admin/reports`
- `GET`: Reports Index
  Filters/params:
  - `filter` (string, optional) A string used to filter reports. Allowed filter terms:
- `type:`: filter by report type. (exact match - lowercase)
- `title:`: filter the title for a string. (case insensitive substring filter)
- If no prefix is provided, the filter will be conducted on the type.
  - `sort` (string, optional) Field to sort by - either created_at or updated_at (pattern: ^(created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)

### `/v1/admin/reports/{report_type}`
- `POST`: Generate Report By Type
  Filters/params:
  - `hours_back` (integer, optional) Number of days back to generate the report for (default: 24)

### `/v1/admin/reports/{report_uuid}`
- `DELETE`: Delete Report
  Filters/params:
  - `commit` (boolean, optional) Whether to commit the action to the database. (default: False)
- `GET`: Get Report

### `/v1/admin/schedules`
- `DELETE`: Delete All Schedules
  Filters/params:
  - `commit` (boolean, optional) Whether to commit the action to the database. (default: False)
- `GET`: Get All Schedules
- `POST`: Post All Schedules

### `/v1/admin/schedules/{name}`
- `DELETE`: Delete Schedule
  Filters/params:
  - `commit` (boolean, optional) Whether to commit the action to the database. (default: False)
- `GET`: Get Schedule
- `POST`: Post Schedule
  Filters/params:
  - `start_now` (boolean, optional) Whether to start the schedule immediately after applying. (default: False)

### `/v1/admin/seed/dev`
- `DELETE`: Delete Seeded Data
  Filters/params:
  - `confirm` (boolean, optional) Must be true to confirm deletion (default: False)
- `POST`: Seed Dev Data
  Filters/params:
  - `count` (integer, optional) Number of stories to create (1-50) (min: 1; max: 50; default: 5)
  - `include_entities` (boolean, optional) Whether to create sample entities (default: True)

### `/v1/admin/seed/dev/status`
- `GET`: Seed Status

### `/v1/agent/tools/find_affected_products`
- `POST`: Find Affected Products Endpoint

### `/v1/agent/tools/ingest_reference`
- `POST`: Ingest Reference Endpoint

### `/v1/agent/tools/search_attack_patterns`
- `POST`: Search Attack Patterns Endpoint

### `/v1/agent/tools/search_embeddings`
- `POST`: Search Embeddings Endpoint

### `/v1/agent/tools/search_vulnerabilities`
- `POST`: Search Vulnerabilities Endpoint

### `/v1/agent/tools/web_search`
- `POST`: Web Search Endpoint

### `/v1/api-keys`
- `GET`: Get Api Keys Route
- `POST`: Create Api Key Route

### `/v1/api-keys/{api_key_uuid}`
- `DELETE`: Delete Api Key Route

### `/v1/attack_patterns`
- `GET`: Attack Patterns Index
  Filters/params:
  - `filter` (string, optional) A string used to filter attack patterns. It can start with specific prefixes to indicate the type of filter:
- `mitre_id:`: Filter by MITRE ATT&CK ID (e.g., 'mitre_id:T1566').
- `tactic:`: Filter by tactic (e.g., 'tactic:initial-access').
- `name:`: Filter by name (partial match, case-insensitive).
- `subtechnique:`: Filter by subtechnique status ('subtechnique:true' or 'subtechnique:false').
- `uuid:`: Filter by UUID.
If no prefix is provided, it defaults to a name filter.
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `sort` (string, optional) Field to sort by - name, mitre_attack_id, created_at, updated_at, trending_1d, trending_7d, or trending_30d (pattern: ^(name|mitre_attack_id|created_at|updated_at|trending_1d|trending_7d|trending_30d)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/attack_patterns/trending/diff`
- `GET`: Trending Diff Endpoint
  Filters/params:
  - `window` (string, optional) Time window for comparison. Format: '<number><unit>' where unit is 'd' (days) or 'h' (hours). Examples: '1d', '12h', '7d'. Maximum: 30d or 720h. Default: '1d'. (pattern: ^\d+[dh]$; default: 1d)
  - `trending_limit` (integer, optional) Maximum number of entities to consider as 'trending' per period. Only the top N entities by mention count are compared. Default: 10. (min: 1; max: 100; default: 10)

### `/v1/attack_patterns/{identifier}`
- `GET`: Single Attack Pattern

### `/v1/attack_patterns/{identifier}/malware`
- `GET`: Single Attack Pattern Malware
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/attack_patterns/{identifier}/mentions`
- `GET`: Single Attack Pattern Mentions
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|published_at|source)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'user_generated_content:true' or 'user_generated_content:false')

### `/v1/attack_patterns/{identifier}/threat_actors`
- `GET`: Single Attack Pattern Threat Actors
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/breaches`
- `GET`: Breaches Index
  Filters/params:
  - `filter` (string, optional) A string used to filter breaches. It can start with specific prefixes to indicate the type of filter:
- `name:`: Filter by Name, case-insensitive.
- `uuid:`: Filter by UUID (exact match).
- `internal_name:`: Filter by internal_name (exact match).
- `loss_type:`: Filter by loss type (array contains).
- `record_type:`: Filter by affected record type (array contains).
If no prefix is provided, it defaults to filtering on the display_name or name fields.
Examples:
- `name:Adobe`
- `internal_name:adobe`
- `loss_type:Passwords`
- `record_type:Email addresses`
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `sort` (string, optional) Field to sort by - name, created_at, updated_at, breach_occurred_at, breach_reported_at, or affected_records (pattern: ^(name|created_at|updated_at|breach_occurred_at|breach_reported_at|affected_records)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; max: 1000; default: 100)
  - `include_merged` (boolean, optional) Include entities that have been merged into other entities (default: False)
  - `verified_only` (boolean, optional) Only return verified breaches (default: False)
  - `exclude_fabricated` (boolean, optional) Exclude fabricated breaches (default: False)
  - `breach_occurred_after` (string | null, optional) Filter breaches that occurred after this date
  - `breach_occurred_before` (string | null, optional) Filter breaches that occurred before this date
  - `breach_reported_after` (string | null, optional) Filter breaches reported after this date
  - `breach_reported_before` (string | null, optional) Filter breaches reported before this date
  - `is_stealer_breach` (boolean | null, optional) Filter by stealer breach status. true = only stealer breaches, false = exclude stealer breaches.
  - `affected_records_gte` (integer | null, optional) Minimum number of affected records
  - `affected_records_lte` (integer | null, optional) Maximum number of affected records
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/breaches/{identifier}`
- `GET`: Lookup Breach

### `/v1/breaches/{identifier}/organizations`
- `GET`: Breach Organizations
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|created_at|updated_at)$; default: name)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: asc)

### `/v1/content_chunks`
- `GET`: Content Chunks Index
  Filters/params:
  - `filter` (string, optional) A string used to filter content chunks. The filter will be conducted within the content chunk embeddings.
  - `sort` (string, optional) Field to sort by - either created_at, updated_at or analyzed_at (pattern: ^(created_at|updated_at|analyzed_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `labels` (array[string], optional) Filter by topic labels (e.g., malware, ransomware, vulnerability). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `format_labels` (array[string], optional) Filter by format labels (e.g., blog_post, news_article, research_paper). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `source_type_labels` (array[string], optional) Filter by source type labels (e.g., government_advisory, threat_intel_vendor). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `depth_labels` (array[string], optional) Filter by depth labels (e.g., technical_deep_dive). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/content_chunks/search`
- `GET`: Content Chunks Search
  Filters/params:
  - `filter` (string, optional) A string used to filter content chunks. The filter will be conducted within the content chunk embeddings.
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; exclusiveMax: 100; default: 10)

### `/v1/content_chunks/{identifier}`
- `GET`: Lookup Content Chunk

### `/v1/dashboards/current-events`
- `GET`: Current Events Dashboard
  Filters/params:
  - `sort` (string, optional) Field to sort by - either created_at or updated_at (pattern: ^(created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)

### `/v1/dashboards/vulnerabilities`
- `GET`: Vulnerabilities Dashboard
  Filters/params:
  - `limit` (integer, optional) Maximum number of vulnerabilities per trending group (min: 1; max: 100; default: 24)

### `/v1/dashboards/{report_type}/latest`
- `GET`: Get Latest Dashboard

### `/v1/dashboards/{report_uuid}`
- `GET`: Get Report

### `/v1/detection_signatures`
- `GET`: Detection Signature Index
  Filters/params:
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either name, created_at or updated_at (pattern: ^(name|created_at|updated_at|enriched_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/detection_signatures/{identifier}`
- `GET`: Lookup Detection Signature

### `/v1/exploitations`
- `GET`: Exploitations Index
  Filters/params:
  - `filter` (string, optional) Filter the exploitations by vulnerability_uuid, cve_id, source, begins_at, or ends_at.  It can start with specific prefixes to indicate the type of filter:
- `vulnerability_uuid:`: Filter by vulnerability UUID.
- `cve_id:`: Filter by CVE ID.
- `source:`: Filter by source.
- `begins_at{operator}`: Filter by begins_at.  Allowed operators are: <, <=, =, >=, > (e.g. `begins_at>2025-11-01`)
- `ends_at{operator}`: Filter by ends_at.  Allowed operators are: <, <=, =, >=, > (e.g. `ends_at<2025-11-01`)
- If no prefix is provided, it defaults to filtering on the vulnerability_uuid, cve_id, and source fields.
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either count, created_at, updated_at, enriched_at, begins_at or ends_at (pattern: ^(count|created_at|updated_at|enriched_at|begins_at|ends_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/exploitations/{identifier}`
- `GET`: Lookup Exploitation

### `/v1/exploits`
- `GET`: Exploits Index
  Filters/params:
  - `filter` (string, optional) A string used to filter exploits. It can start with specific prefixes to indicate the type of filter:
- `uuid:`: Filter by UUID.
- `url:`: Filter by url.
- `authors:`: Filter by authors.
- `maturity:`: Filter by maturity.
- If the filter string matches a UUID pattern, it will be treated as a specific filter.
- If no prefix is provided, it defaults to a url filter.
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `sort` (string, optional) Field to sort by - one of: url, authors, maturity, disclosed_at, created_at, or updated_at (pattern: ^(url|authors|maturity|disclosed_at|created_at|updated_at|enriched_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/exploits/{identifier}`
- `GET`: Lookup Exploit

### `/v1/exploits/{identifier}/enrich`
- `POST`: Enrich Exploit

### `/v1/exploits/{identifier}/export`
- `GET`: Export Exploit
  Filters/params:
  - `relationships_created_after` (string | null, optional) Filter related objects to only include those created after this ISO8601/RFC3339 timestamp
  - `relationships_created_before` (string | null, optional) Filter related objects to only include those created before this ISO8601/RFC3339 timestamp

### `/v1/exploits/{identifier}/vulnerabilities`
- `GET`: Exploit Vulnerabilities
  Filters/params:
  - `filter` (string, optional) A string used to filter vulnerabilities. It can start with specific prefixes to indicate the type of filter:
- `cve:`: Filter by CVE ID.
- `desc:`: Filter by description.
- If the filter string matches the pattern `CVE-`, it will be treated as a CVE filter.
- If no prefix is provided, it defaults to searching both CVE ID and description. (default: )
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by: cve_id, created_at, updated_at, cvss_base_score, or epss_score (pattern: ^(cve_id|created_at|updated_at|cvss_base_score|epss_score)$; default: cve_id)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: asc)

### `/v1/exports`
- `GET`: List Exports
  Filters/params:
  - `export_type` (string, optional) Type of export to retrieve. Allowed: vuln_intel (default: vuln_intel)
  - `export_strategy` (string | null, optional) Filter by export strategy
  - `limit` (integer, optional) Number of exports to return (min: 1; max: 100; default: 10)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/exports/history`
- `GET`: Get Export History
  Filters/params:
  - `export_type` (string, optional) Type of export to retrieve. Allowed: vuln_intel (default: vuln_intel)
  - `export_strategy` (string | null, optional) Filter by export strategy
  - `limit` (integer, optional) Number of exports to return (min: 1; max: 100; default: 10)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/exports/latest`
- `GET`: Get Latest Export Url
  Filters/params:
  - `export_type` (string, optional) Type of export to retrieve. Allowed: vuln_intel (default: vuln_intel)
  - `export_strategy` (string, optional) Export strategy: full or incremental (default: incremental)
  - `expires_in` (integer, optional) Signed URL expiration time in seconds (300-86400) (min: 300; max: 86400; default: 86400)

### `/v1/exports/{uuid}`
- `GET`: Get Export Url By Uuid
  Filters/params:
  - `expires_in` (integer, optional) Signed URL expiration time in seconds (300-86400) (min: 300; max: 86400; default: 86400)

### `/v1/followed_entities`
- `GET`: Followed Entities Index
  Filters/params:
  - `filter` (string, optional) Filter using prefix syntax:
- `entity_type:`: filter by entity type (e.g., entity_type:vulnerability)
- `uuid:`: filter by UUID prefix
  - `sort` (string, optional) Field to sort by (pattern: ^(uuid|created_at|updated_at|entity_type)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; default: 50)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value
- `POST`: Create Followed Entity
- `PUT`: Bulk Set Followed Entities

### `/v1/followed_entities/{uuid}`
- `DELETE`: Delete Followed Entity
- `GET`: Get Followed Entity By Uuid
- `PATCH`: Update Followed Entity

### `/v1/followed_topics`
- `GET`: Followed Topics Index
  Filters/params:
  - `filter` (string, optional) Filter using prefix syntax:
- `topic:`: filter by topic prefix (e.g., topic:ransom)
- `uuid:`: filter by UUID prefix
  - `sort` (string, optional) Field to sort by (pattern: ^(uuid|created_at|updated_at|topic)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; default: 50)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value
- `POST`: Create Followed Topic
- `PUT`: Bulk Set Followed Topics

### `/v1/followed_topics/{uuid}`
- `DELETE`: Delete Followed Topic
- `GET`: Get Followed Topic By Uuid
- `PATCH`: Update Followed Topic

### `/v1/health`
- `GET`: Health Check

### `/v1/industries`
- `GET`: Get Gics Codes

### `/v1/industries/{code}`
- `GET`: Get Industry By Code

### `/v1/integrations`
- `GET`: List Integrations
  Filters/params:
  - `filter` (string | null, optional) Filter by name or type. Use 'type:value' for type filter, 'name:value' or plain text for name filter (case-insensitive)
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 500)
- `POST`: Create Integration

### `/v1/integrations/meta/capabilities`
- `GET`: Get Integration Capabilities

### `/v1/integrations/meta/schemas`
- `GET`: Get Integration Schemas

### `/v1/integrations/{integration_uuid}`
- `DELETE`: Delete Integration
  Filters/params:
  - `force` (boolean, optional) Force deletion even if schedules are using this integration (default: False)
- `GET`: Get Integration
- `PATCH`: Update Integration

### `/v1/integrations/{integration_uuid}/actions/{action}`
- `POST`: Execute Integration Action

### `/v1/malware`
- `GET`: Malware Index
  Filters/params:
  - `filter` (string, optional) A string used to filter malware. It can start with specific prefixes to indicate the type of filter:
- `name:`: Filter by Name.
- `uuid:`: Filter by UUID.
- `internal_name:`: Filter by internal_name (exact match).
- `desc:`: Filter by description (searches both description and gen_description fields).
- If no prefix is provided, it defaults to a name filter.
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `sort` (string, optional) Field to sort by - either name, created_at, updated_at, enriched_at, trending_1d, trending_7d, or trending_30d (pattern: ^(name|created_at|updated_at|enriched_at|trending_1d|trending_7d|trending_30d)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `include_merged` (boolean, optional) Include entities that have been merged into other entities (default: False)
  - `followed` (boolean, optional) When true, returns only malware that the tenant is following (default: False)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/malware/trending/diff`
- `GET`: Trending Diff Endpoint
  Filters/params:
  - `window` (string, optional) Time window for comparison. Format: '<number><unit>' where unit is 'd' (days) or 'h' (hours). Examples: '1d', '12h', '7d'. Maximum: 30d or 720h. Default: '1d'. (pattern: ^\d+[dh]$; default: 1d)
  - `trending_limit` (integer, optional) Maximum number of entities to consider as 'trending' per period. Only the top N entities by mention count are compared. Default: 10. (min: 1; max: 100; default: 10)

### `/v1/malware/{identifier}`
- `GET`: Lookup Malware

### `/v1/malware/{identifier}/attack_patterns`
- `GET`: Single Malware Attack Patterns
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|mitre_attack_id|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/malware/{identifier}/enrich`
- `POST`: Enrich Malware

### `/v1/malware/{identifier}/export`
- `GET`: Export Malware
  Filters/params:
  - `relationships_created_after` (string | null, optional) Filter related objects to only include those created after this ISO8601/RFC3339 timestamp
  - `relationships_created_before` (string | null, optional) Filter related objects to only include those created before this ISO8601/RFC3339 timestamp

### `/v1/malware/{identifier}/mentions`
- `GET`: Single Malware Mentions
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|published_at|source)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'user_generated_content:true' or 'user_generated_content:false')

### `/v1/malware/{identifier}/observables`
- `GET`: Single Malware Observables
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(type|name|created_at|published_at)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'type:ip.v4', 'type:domain', 'type:hash.sha256')

### `/v1/malware/{identifier}/vulnerabilities`
- `GET`: Single Malware Vulnerabilities
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(cve_id|created_at|updated_at|published_at|cvss_base_score)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/mentions`
- `GET`: Mentions Index
  Filters/params:
  - `entity_type` (string | null, optional) Filter by entity type (e.g., organization, threat_actor, vulnerability, malware, technology_product)
  - `offset` (integer, optional) Number of items to skip before starting to collect results (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|published_at|collected_at)$; default: published_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/mentions/actors`
- `GET`: Actor Mentions Index
  Filters/params:
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either created_at, updated_at, published_at, or collected_at (pattern: ^(created_at|updated_at|published_at|collected_at)$; default: published_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/mentions/vulnerabilities`
- `GET`: Vulnerability Mentions Index
  Filters/params:
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either created_at, updated_at, published_at, or collected_at (pattern: ^(created_at|updated_at|published_at|collected_at)$; default: published_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/observables`
- `GET`: Observables Index
  Filters/params:
  - `filter` (string, optional) Filter using prefix syntax:
- `type:`: filter by observable type prefix or exact match (e.g., type:ip or type:ip.v4)
- `name:`: filter by observable name (case insensitive)
- `uuid:`: filter by UUID (partial match)
- If no prefix is provided, filters by name
  - `sort` (string, optional) Field to sort by (pattern: ^(uuid|created_at|updated_at|type|name)$; default: uuid)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; default: 100)
  - `scope` (string, optional) Scope filter to optionally limit the results to global or tenant data. If no scope is provided, then both global and tenant data are returned. The scope can be one of the following: - global: only global data
- tenant: only tenant-specific data (pattern: ^(global|tenant)$)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value
- `POST`: Create Observable

### `/v1/observables/{observable_type}/{observable_name}/opinions`
- `GET`: Get Opinions By Observable Type And Name
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(uuid|created_at|published_at|observable_type|observable_name|source)$; default: uuid)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `scope` (string, optional) Scope filter to optionally limit the results to global or tenant data. If no scope is provided, the default is to return both global and tenant data.  The scope can be one of the following: - global: only global data
- tenant: only tenant-specific data (pattern: ^(global|tenant)$)

### `/v1/observables/{type}/{name}`
- `GET`: Get Observable By Type And Name
  Filters/params:
  - `scope` (string, optional) Scope filter to optionally limit the results to global or tenant data. The scope can be one of the following: - global: only global data
- tenant: only tenant-specific data
If no scope is provided, then the first matching Observable from global and tenant data, with tenant data preferred first. (pattern: ^(global|tenant)$)

### `/v1/observables/{uuid}`
- `DELETE`: Delete Observable
- `GET`: Get Observable By Uuid
- `PATCH`: Update Observable

### `/v1/observables/{uuid}/opinions`
- `GET`: Get Opinions By Observable Uuid
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(uuid|created_at|published_at|observable_type|source)$; default: uuid)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `scope` (string, optional) Scope filter to optionally limit the results to global or tenant data. The scope can be one of the following: - global: only global data
- tenant: only tenant-specific data
If no scope is provided, then the first matching Observable from global and tenant data, with tenant data preferred first. (pattern: ^(global|tenant)$)

### `/v1/opinions`
- `GET`: Opinions Index
  Filters/params:
  - `filter` (string, optional) Filter using prefix syntax:
- `type:`: filter by observable type prefix or exact match, case sensitive (e.g., type:ip or type:ip.v4)
- `name:`: filter by observable name prefix or exact match, case sensitive
- `source:`: filter by source (case insensitive)
- `uuid:`: filter by UUID (prefix or exact match)
- If no prefix is provided, searches across type, name, and source
  - `sort` (string, optional) Field to sort by (pattern: ^(uuid|created_at|published_at|observable_type|source)$; default: uuid)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; default: 100)
  - `scope` (string, optional) Scope filter to optionally limit the results to global or tenant data. The scope can be one of the following: - global: only global data
- tenant: only tenant-specific data
If no scope is provided, then both global and tenant data are returned. (pattern: ^(global|tenant)$)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value
  - `published_at__gte` (string | null, optional) Filter on the published_at field for items greater than or equal to the given value
  - `published_at__lt` (string | null, optional) Filter on the published_at field for items less than the given value
- `POST`: Create Opinion

### `/v1/opinions/grouped`
- `GET`: Get Grouped Opinions
  Filters/params:
  - `type` (string | null, optional) Filter by observable type (e.g., ip.v4, domain)
  - `verdict` (string | null, optional) Comma-separated list of verdicts to filter by (e.g., malicious,suspicious)
  - `source` (string | null, optional) Comma-separated list of sources to filter by (exact match)
  - `observable_name` (string | null, optional) Filter by observable name (case-insensitive contains search). Use this to search for specific IPs, domains, hashes, etc.
  - `sort` (string, optional) Field to sort by (pattern: ^(observable_name|observable_type|published_at)$; default: published_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) Number of grouped observables to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of grouped observables to return (min: 1; max: 200; default: 50)
  - `scope` (string | null, optional) Scope filter to optionally limit the results to global or tenant data. If no scope is provided, then both global and tenant data are returned.
  - `published_at__gte` (string | null, optional) Filter on the published_at field for items greater than or equal to the given value
  - `published_at__lt` (string | null, optional) Filter on the published_at field for items less than the given value

### `/v1/opinions/{uuid}`
- `DELETE`: Delete Opinion
- `GET`: Get Opinion By Uuid
- `PATCH`: Update Opinion

### `/v1/organizations`
- `GET`: Organizations Index
  Filters/params:
  - `filter` (string, optional) A string used to filter organizations. It can start with specific prefixes to indicate the type of filter:
- `name:`: Filter by Name, case-insensitive.
- `uuid:`: Filter by UUID, case-insensitive.
- `internal_name:`: Filter by internal_name (exact match).
- `desc:`: Filter by description (searches both description and gen_description fields).
If no prefix is provided, it defaults to filtering on the display_name or name fields.
Examples:
- `name:Microsoft`
- `name:apple`
- `internal_name:microsoft_corporation`
- `Microsoft Corporation`
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `sort` (string, optional) Field to sort by - either name, created_at, updated_at, enriched_at, trending_1d, trending_7d, or trending_30d (pattern: ^(name|created_at|updated_at|enriched_at|trending_1d|trending_7d|trending_30d)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `include_merged` (boolean, optional) Include entities that have been merged into other entities (default: False)
  - `followed` (boolean, optional) When true, returns only organizations that the tenant is following (default: False)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/organizations/trending/diff`
- `GET`: Trending Diff Endpoint
  Filters/params:
  - `window` (string, optional) Time window for comparison. Format: '<number><unit>' where unit is 'd' (days) or 'h' (hours). Examples: '1d', '12h', '7d'. Maximum: 30d or 720h. Default: '1d'. (pattern: ^\d+[dh]$; default: 1d)
  - `trending_limit` (integer, optional) Maximum number of entities to consider as 'trending' per period. Only the top N entities by mention count are compared. Default: 10. (min: 1; max: 100; default: 10)

### `/v1/organizations/{identifier}`
- `GET`: Lookup Organization

### `/v1/organizations/{identifier}/breaches`
- `GET`: Single Organization Breaches
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|created_at|updated_at|breach_occurred_at|breach_reported_at)$; default: breach_occurred_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/organizations/{identifier}/enrich`
- `POST`: Enrich Organization

### `/v1/organizations/{identifier}/export`
- `GET`: Export Organization
  Filters/params:
  - `relationships_created_after` (string | null, optional) Filter related objects to only include those created after this ISO8601/RFC3339 timestamp
  - `relationships_created_before` (string | null, optional) Filter related objects to only include those created before this ISO8601/RFC3339 timestamp

### `/v1/organizations/{identifier}/mentions`
- `GET`: Single Organization Mentions
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|published_at|source)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'user_generated_content:true' or 'user_generated_content:false')

### `/v1/organizations/{identifier}/products`
- `GET`: Single Organization Products
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/products`
- `GET`: Product Index
  Filters/params:
  - `filter` (string, optional) A string used to filter products. It can start with specific prefixes to indicate the type of filter:
- `name:`: Filter by Name.
- `internal_name:`: Filter by internal_name (exact match).
- `desc:`: Filter by description (searches both description and gen_description fields).
- If no prefix is provided, it defaults to a name filter. (default: )
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either name, created_at, updated_at, enriched_at, trending_1d, trending_7d, or trending_30d (pattern: ^(name|created_at|updated_at|enriched_at|trending_1d|trending_7d|trending_30d)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `include_merged` (boolean, optional) Include entities that have been merged into other entities (default: False)
  - `followed` (boolean, optional) When true, returns only products that the tenant is following (default: False)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/products/search`
- `POST`: Search Products
  Filters/params:
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either name, created_at or updated_at (pattern: ^(name|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)

### `/v1/products/trending/diff`
- `GET`: Trending Diff Endpoint
  Filters/params:
  - `window` (string, optional) Time window for comparison. Format: '<number><unit>' where unit is 'd' (days) or 'h' (hours). Examples: '1d', '12h', '7d'. Maximum: 30d or 720h. Default: '1d'. (pattern: ^\d+[dh]$; default: 1d)
  - `trending_limit` (integer, optional) Maximum number of entities to consider as 'trending' per period. Only the top N entities by mention count are compared. Default: 10. (min: 1; max: 100; default: 10)

### `/v1/products/{identifier}`
- `GET`: Lookup Product

### `/v1/products/{identifier}/enrich`
- `POST`: Enrich Product

### `/v1/products/{identifier}/export`
- `GET`: Export Product
  Filters/params:
  - `relationships_created_after` (string | null, optional) Filter related objects to only include those created after this ISO8601/RFC3339 timestamp
  - `relationships_created_before` (string | null, optional) Filter related objects to only include those created before this ISO8601/RFC3339 timestamp

### `/v1/products/{identifier}/mentions`
- `GET`: Single Product Mentions
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|published_at|source)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'user_generated_content:true' or 'user_generated_content:false')

### `/v1/products/{identifier}/technology_product_advisories`
- `GET`: Single Product Technology Product Advisories

### `/v1/products/{product_uuid}`
- `PATCH`: Update Product

### `/v1/references`
- `GET`: References Index
  Filters/params:
  - `filter` (string, optional) A string used to filter references. Allowed filter terms:
- `source:`: filter by source. (exact match - lowercase)
- `domain:`: filter by domain. (case insensitive substring filter)
- `url:`: filter by url. (case insensitive substring filter)
- `final_url:`: filter by final_url. (case insensitive substring)
- `title:`: filter the title for a string. (case insensitive substring filter)
- `topic:`: filter the topic for a string. (case insensitive substring filter)
- `label:`: filter by content chunk label (exact match)
- `embedding:`: filter by content chunk embedding (semantic search)
- `last_http_status:`: filter by last_http_status (exact match)
- `type:`: filter by type. (exact match - converted to uppercase)
- If no prefix is provided, the filter will be conducted on the url.
Use published_at__gte and published_at__lt params for date filtering (half-open interval [start, end)).
  - `sort` (string, optional) Field to sort by - either created_at, updated_at, published_at, first_collected_at, or last_collected_at (pattern: ^(published_at|first_collected_at|last_collected_at|created_at|updated_at)$; default: published_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `labels` (array[string], optional) Filter by topic labels (e.g., malware, ransomware, vulnerability). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `format_labels` (array[string], optional) Filter by format labels (e.g., blog_post, news_article, research_paper). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `source_type_labels` (array[string], optional) Filter by source type labels (e.g., government_advisory, threat_intel_vendor). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `depth_labels` (array[string], optional) Filter by depth labels (e.g., technical_deep_dive). Multiple values use OR matching. Combined with other label category params using AND. (default: [])
  - `source` (string | null, optional) Filter on the source field by exact match
  - `source__in` (string | null, optional) Filter on the source field for items that match any value in a comma-separated list
  - `user_generated_content` (boolean | null, optional) Filter on the user_generated_content field by exact match
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value
  - `published_at__gte` (string | null, optional) Filter on the published_at field for items greater than or equal to the given value
  - `published_at__lt` (string | null, optional) Filter on the published_at field for items less than the given value
- `POST`: Create References

### `/v1/references/labels`
- `GET`: Get Content Labels

### `/v1/references/{identifier}`
- `GET`: Lookup Reference

### `/v1/references/{identifier}/entities`
- `GET`: Get Reference Entities

### `/v1/references/{identifier}/reanalyze`
- `POST`: Reanalyze Reference

### `/v1/references/{identifier}/reingest`
- `POST`: Reingest Reference

### `/v1/references/{identifier}/threat-actor-mentions`
- `GET`: Get Threat Actor Mentions

### `/v1/references/{identifier}/threat-actors`
- `GET`: Get Threat Actors

### `/v1/references/{identifier}/vulnerabilities`
- `GET`: Get Vulnerabilities

### `/v1/references/{identifier}/vulnerability-mentions`
- `GET`: Get Vulnerability Mentions

### `/v1/schedules`
- `GET`: List Schedules
  Filters/params:
  - `filter` (string | null, optional) Case-insensitive search on the prompt field
  - `status` (string | null, optional) Filter by status, one of: active, paused
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value
- `POST`: Create Schedule

### `/v1/schedules/{schedule_uuid}`
- `DELETE`: Delete Schedule
- `GET`: Get Schedule
- `PATCH`: Update Schedule

### `/v1/schedules/{schedule_uuid}/executions`
- `GET`: Get Schedule Executions
  Filters/params:
  - `limit` (integer, optional) Maximum number of executions to return (min: 1; max: 500; default: 100)
  - `offset` (integer, optional) Number of executions to skip (min: 0; default: 0)

### `/v1/search`
- `GET`: Search
  Filters/params:
  - `q` (string, required) The query to search for.  This works like typical web search, where you can quote phrases to search for them exactly, use OR to search for multiple words, and prefix a term with - as a negative filter.

Examples:
- "CVE-2024-12345"
- "CVE-2024-12345 OR CVE-2024-12346"
- "Lapsus OR Lap$us -ShinyHunters"
  - `types` (array[string], optional) The types of entries to search for.  Defaults to all types.  Valid types are: threat_actor, vulnerability, exploit, organization, technology_product, advisory, malware, story (default: [])
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (default: 20)

### `/v1/sources`
- `GET`: Sources Index
  Filters/params:
  - `filter` (string, optional) A string used to filter sources. Allowed filter terms:
- `type:`: filter by reference type. Valid values: UNSTRUCTURED, STRUCTURED, SYNTHETIC, STRUCTURED_SOCIAL (case insensitive)
- `slug:`: filter by slug. (case insensitive substring filter)
- If no prefix is provided, the filter will be conducted on the slug.

### `/v1/sources/{source}/statistics`
- `GET`: Source Statistics

### `/v1/stories`
- `GET`: Stories Index
  Filters/params:
  - `filter` (string, optional) A string used to filter stories. Allowed filter terms:
- `title:`: filter by title (case insensitive substring)
- `description:`: filter by description (case insensitive substring)
- `min_refs:`: filter by minimum reference count (e.g., min_refs:5)
- `max_refs:`: filter by maximum reference count (e.g., max_refs:10)
- `topic:`: filter by topic labels (comma-separated, OR logic, e.g., topic:ransomware,malware)
- If no prefix is provided, the filter will search in the title.
  - `topics` (array[string], optional) Filter by topic labels. Pass multiple values for OR logic (e.g., topics=ransomware&topics=malware). This is an alternative to using `filter=topic:...`. (default: [])
  - `sort` (string, optional) Field to sort by - either created_at, updated_at, title, or reference_count (pattern: ^(created_at|updated_at|title|reference_count)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; max: 1000; default: 100)
  - `followed_entities` (boolean, optional) When true, returns only stories that mention entities the tenant is following (default: False)
  - `followed_topics` (boolean, optional) When true, returns only stories with topic labels matching topics the tenant is following (default: False)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/stories/merge`
- `POST`: Merge Stories Endpoint
  Filters/params:
  - `preview` (boolean, optional) Preview mode - show what would happen without making changes (default: False)

### `/v1/stories/topics`
- `GET`: Story Topics
  Filters/params:
  - `sort` (string, optional) Field to sort by (pattern: ^(story_count|latest_story_timestamp)$; default: story_count)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `story_count__gt` (integer | null, optional) Filter topics with story count greater than this value
  - `story_count__gte` (integer | null, optional) Filter topics with story count greater than or equal to this value
  - `story_count__lt` (integer | null, optional) Filter topics with story count less than this value
  - `story_count__lte` (integer | null, optional) Filter topics with story count less than or equal to this value
  - `latest_story_timestamp__gt` (string | null, optional) Filter topics with latest story timestamp greater than this ISO8601 date
  - `latest_story_timestamp__gte` (string | null, optional) Filter topics with latest story timestamp greater than or equal to this ISO8601 date
  - `latest_story_timestamp__lt` (string | null, optional) Filter topics with latest story timestamp less than this ISO8601 date
  - `latest_story_timestamp__lte` (string | null, optional) Filter topics with latest story timestamp less than or equal to this ISO8601 date

### `/v1/stories/unmerge`
- `POST`: Unmerge Story Endpoint
  Filters/params:
  - `preview` (boolean, optional) Preview mode - show what would be restored without making changes (default: False)

### `/v1/stories/{identifier}`
- `DELETE`: Delete Story
- `GET`: Single Story
  Filters/params:
  - `include_merged` (boolean, optional) Include stories that have been merged into other stories (default: False)
- `PATCH`: Update Story

### `/v1/stories/{identifier}/enrich`
- `POST`: Enrich Story

### `/v1/stories/{identifier}/entities`
- `GET`: Story Entities
  Filters/params:
  - `threshold` (number, optional) Minimum saliency score threshold (range: 0 to 1) (min: 0.0; max: 1.0; default: 0.5)
  - `entity_type` (string | null, optional) Filter by entity type: vulnerability, threat_actor, malware, technology_product, or organization

### `/v1/stories/{identifier}/events`
- `GET`: Story Events
  Filters/params:
  - `filter` (string, optional) Filter parameter (e.g., 'event_type:story_created', 'event_type:reference_assigned')
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; max: 1000; default: 100)

### `/v1/stories/{identifier}/export`
- `GET`: Export Story
  Filters/params:
  - `include_analysis` (boolean, optional) Include analysis objects for content chunks (default: True)

### `/v1/stories/{identifier}/generate-image`
- `POST`: Generate Story Image Endpoint
  Filters/params:
  - `async_mode` (boolean, optional) If true, returns immediately with workflow_id. If false (default), waits for completion. (default: False)

### `/v1/stories/{identifier}/references`
- `GET`: Story References
  Filters/params:
  - `sort` (string, optional) Field to sort by - either published_at, created_at, updated_at, title, or source_slug (pattern: ^(published_at|created_at|updated_at|title|source_slug)$; default: published_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; max: 1000; default: 100)

### `/v1/stories/{identifier}/similar`
- `GET`: Similar Stories
  Filters/params:
  - `threshold` (number, optional) Similarity threshold (higher values are more similar, range: -1 to 1) (min: -1.0; max: 1.0; default: 0.6)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; max: 100; default: 10)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/technology_product_advisories`
- `GET`: Technology Product Advisories Index
  Filters/params:
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either created_at, updated_at, source, or name (pattern: ^(created_at|updated_at|source|name)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/technology_product_advisories/{identifier}`
- `GET`: Single Technology Product Advisory

### `/v1/technology_product_advisories/{identifier}/export`
- `GET`: Export Technology Product Advisory
  Filters/params:
  - `relationships_created_after` (string | null, optional) Filter related objects to only include those created after this ISO8601/RFC3339 timestamp
  - `relationships_created_before` (string | null, optional) Filter related objects to only include those created before this ISO8601/RFC3339 timestamp

### `/v1/technology_product_advisories/{identifier}/products`
- `GET`: Single Technology Product Advisory Products
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by - name, vendor_name, or created_at (pattern: ^(name|vendor_name|created_at)$; default: name)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: asc)
  - `type` (string, optional) Output model type. Use 'basic' (default) for standard fields or 'detailed' for additional fields including relationships and extended metadata. (pattern: ^(basic|detailed)$; default: basic)

### `/v1/technology_product_advisories/{identifier}/vulnerabilities`
- `GET`: Single Technology Product Advisory Vulnerabilities
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by - cve_id, cvss_base_score, epss_score, or published_at (pattern: ^(cve_id|cvss_base_score|epss_score|published_at)$; default: epss_score)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `type` (string, optional) Output model type. Use 'basic' (default) for standard fields or 'detailed' for additional fields including relationships and extended metadata. (pattern: ^(basic|detailed)$; default: basic)

### `/v1/tenants/{tenant_uuid}`
- `GET`: Get Tenant
- `PATCH`: Update Tenant

### `/v1/user`
- `GET`: Get User

### `/v1/user/token`
- `POST`: Create Sign In Token

### `/v1/vulnerabilities`
- `GET`: Vulnerabilities Index
  Filters/params:
  - `filter` (string, optional) A string used to filter vulnerabilities. It can start with specific prefixes to indicate the type of filter:
- `cve:`: Filter by CVE ID.
- `uuid:`: Filter by UUID.
- `internal_name:`: Filter by internal_name (exact match).
- `desc:`: Filter by description (searches both description and gen_description fields).
- `gen_display_name:`: Filter by gen_display_name.
- `cisa_kev:`: Filter by cisa_kev.
- `state:`: Filter by state.
- If the filter string matches the pattern `CVE-` or a UUID pattern, it will be treated as a specific filter.
- If no prefix is provided, it defaults to a description filter (searches both description fields).
  - `sort` (string, optional) Field to sort by - either cve_id, gen_cwe_id, state, created_at, updated_at, enriched_at, published_at, cvss_base_score, cvss_version, epss_score, epss_percentile, trending_1d, trending_7d, or trending_30d (pattern: ^(cve_id|gen_cwe_id|state|created_at|updated_at|enriched_at|published_at|cvss_base_score|cvss_version|epss_score|epss_percentile|trending_1d|trending_7d|trending_30d)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `include_merged` (boolean, optional) Include entities that have been merged into other entities (default: False)
  - `followed` (boolean, optional) When true, returns only vulnerabilities that the tenant is following (default: False)
  - `cvss_base_score` (number | null, optional) Filter on the cvss_base_score field by exact match
  - `cvss_base_score__neq` (number | null, optional) Filter on the cvss_base_score field for items not equal to the given value
  - `cvss_base_score__gt` (number | null, optional) Filter on the cvss_base_score field for items greater than the given value
  - `cvss_base_score__gte` (number | null, optional) Filter on the cvss_base_score field for items greater than or equal to the given value
  - `cvss_base_score__lt` (number | null, optional) Filter on the cvss_base_score field for items less than the given value
  - `cvss_base_score__lte` (number | null, optional) Filter on the cvss_base_score field for items less than or equal to the given value
  - `cvss_base_score__isnull` (boolean | null, optional) Filter on the cvss_base_score field for items that are NULL (true) or NOT NULL (false)
  - `cvss_base_score__exists` (boolean | null, optional) Filter on the cvss_base_score field for items that exist (true/false)
  - `epss_score` (number | null, optional) Filter on the epss_score field by exact match
  - `epss_score__neq` (number | null, optional) Filter on the epss_score field for items not equal to the given value
  - `epss_score__gt` (number | null, optional) Filter on the epss_score field for items greater than the given value
  - `epss_score__gte` (number | null, optional) Filter on the epss_score field for items greater than or equal to the given value
  - `epss_score__lt` (number | null, optional) Filter on the epss_score field for items less than the given value
  - `epss_score__lte` (number | null, optional) Filter on the epss_score field for items less than or equal to the given value
  - `epss_score__isnull` (boolean | null, optional) Filter on the epss_score field for items that are NULL (true) or NOT NULL (false)
  - `epss_score__exists` (boolean | null, optional) Filter on the epss_score field for items that exist (true/false)
  - `epss_percentile` (number | null, optional) Filter on the epss_percentile field by exact match
  - `epss_percentile__neq` (number | null, optional) Filter on the epss_percentile field for items not equal to the given value
  - `epss_percentile__gt` (number | null, optional) Filter on the epss_percentile field for items greater than the given value
  - `epss_percentile__gte` (number | null, optional) Filter on the epss_percentile field for items greater than or equal to the given value
  - `epss_percentile__lt` (number | null, optional) Filter on the epss_percentile field for items less than the given value
  - `epss_percentile__lte` (number | null, optional) Filter on the epss_percentile field for items less than or equal to the given value
  - `epss_percentile__isnull` (boolean | null, optional) Filter on the epss_percentile field for items that are NULL (true) or NOT NULL (false)
  - `epss_percentile__exists` (boolean | null, optional) Filter on the epss_percentile field for items that exist (true/false)
  - `gen_cwe_id` (string | null, optional) Filter on the gen_cwe_id field by exact match
  - `gen_cwe_id__neq` (string | null, optional) Filter on the gen_cwe_id field for items not equal to the given value
  - `gen_cwe_id__in` (string | null, optional) Filter on the gen_cwe_id field for items that match any value in a comma-separated list
  - `gen_cwe_id__not_in` (string | null, optional) Filter on the gen_cwe_id field for items that do not match any value in a comma-separated list
  - `gen_cwe_id__like` (string | null, optional) Filter on the gen_cwe_id field for items that match a SQL LIKE pattern (use % as wildcard, case-sensitive)
  - `gen_cwe_id__ilike` (string | null, optional) Filter on the gen_cwe_id field for items that match a SQL LIKE pattern (use % as wildcard, case-insensitive)
  - `gen_cwe_id__isnull` (boolean | null, optional) Filter on the gen_cwe_id field for items that are NULL (true) or NOT NULL (false)
  - `gen_cwe_id__exists` (boolean | null, optional) Filter on the gen_cwe_id field for items that exist (true/false)
  - `published_at` (string | null, optional) Filter on the published_at field by exact match
  - `published_at__neq` (string | null, optional) Filter on the published_at field for items not equal to the given value
  - `published_at__lt` (string | null, optional) Filter on the published_at field for items less than the given value
  - `published_at__lte` (string | null, optional) Filter on the published_at field for items less than or equal to the given value
  - `published_at__gt` (string | null, optional) Filter on the published_at field for items greater than the given value
  - `published_at__gte` (string | null, optional) Filter on the published_at field for items greater than or equal to the given value
  - `published_at__isnull` (boolean | null, optional) Filter on the published_at field for items that are NULL (true) or NOT NULL (false)
  - `published_at__exists` (boolean | null, optional) Filter on the published_at field for items that exist (true/false)
  - `enriched_at__gte` (string | null, optional) Filter on the enriched_at field for items greater than or equal to the given value
  - `enriched_at__lt` (string | null, optional) Filter on the enriched_at field for items less than the given value
  - `cisa_kev_added_at__gte` (string | null, optional) Filter on the cisa_kev_added_at field for items greater than or equal to the given value
  - `cisa_kev_added_at__lt` (string | null, optional) Filter on the cisa_kev_added_at field for items less than the given value
  - `exploits_count` (integer | null, optional) Filter by exploits count
  - `exploits_count__neq` (integer | null, optional) Filter by exploits count (for items not equal to the given value)
  - `exploits_count__gt` (integer | null, optional) Filter by exploits count (for items greater than the given value)
  - `exploits_count__gte` (integer | null, optional) Filter by exploits count (for items greater than or equal to the given value)
  - `exploits_count__lt` (integer | null, optional) Filter by exploits count (for items less than the given value)
  - `exploits_count__lte` (integer | null, optional) Filter by exploits count (for items less than or equal to the given value)
  - `exploitations_count` (integer | null, optional) Filter by exploitations count
  - `exploitations_count__neq` (integer | null, optional) Filter by exploitations count (for items not equal to the given value)
  - `exploitations_count__gt` (integer | null, optional) Filter by exploitations count (for items greater than the given value)
  - `exploitations_count__gte` (integer | null, optional) Filter by exploitations count (for items greater than or equal to the given value)
  - `exploitations_count__lt` (integer | null, optional) Filter by exploitations count (for items less than the given value)
  - `exploitations_count__lte` (integer | null, optional) Filter by exploitations count (for items less than or equal to the given value)
  - `detection_signatures_count` (integer | null, optional) Filter by detection_signatures count
  - `detection_signatures_count__neq` (integer | null, optional) Filter by detection_signatures count (for items not equal to the given value)
  - `detection_signatures_count__gt` (integer | null, optional) Filter by detection_signatures count (for items greater than the given value)
  - `detection_signatures_count__gte` (integer | null, optional) Filter by detection_signatures count (for items greater than or equal to the given value)
  - `detection_signatures_count__lt` (integer | null, optional) Filter by detection_signatures count (for items less than the given value)
  - `detection_signatures_count__lte` (integer | null, optional) Filter by detection_signatures count (for items less than or equal to the given value)
  - `mentions_count` (integer | null, optional) Filter by mentions count
  - `mentions_count__neq` (integer | null, optional) Filter by mentions count (for items not equal to the given value)
  - `mentions_count__gt` (integer | null, optional) Filter by mentions count (for items greater than the given value)
  - `mentions_count__gte` (integer | null, optional) Filter by mentions count (for items greater than or equal to the given value)
  - `mentions_count__lt` (integer | null, optional) Filter by mentions count (for items less than the given value)
  - `mentions_count__lte` (integer | null, optional) Filter by mentions count (for items less than or equal to the given value)
  - `weaknesses_count` (integer | null, optional) Filter by weaknesses count
  - `weaknesses_count__neq` (integer | null, optional) Filter by weaknesses count (for items not equal to the given value)
  - `weaknesses_count__gt` (integer | null, optional) Filter by weaknesses count (for items greater than the given value)
  - `weaknesses_count__gte` (integer | null, optional) Filter by weaknesses count (for items greater than or equal to the given value)
  - `weaknesses_count__lt` (integer | null, optional) Filter by weaknesses count (for items less than the given value)
  - `weaknesses_count__lte` (integer | null, optional) Filter by weaknesses count (for items less than or equal to the given value)
  - `advisories_count` (integer | null, optional) Filter by advisories count
  - `advisories_count__neq` (integer | null, optional) Filter by advisories count (for items not equal to the given value)
  - `advisories_count__gt` (integer | null, optional) Filter by advisories count (for items greater than the given value)
  - `advisories_count__gte` (integer | null, optional) Filter by advisories count (for items greater than or equal to the given value)
  - `advisories_count__lt` (integer | null, optional) Filter by advisories count (for items less than the given value)
  - `advisories_count__lte` (integer | null, optional) Filter by advisories count (for items less than or equal to the given value)
  - `malware_count` (integer | null, optional) Filter by malware count
  - `malware_count__neq` (integer | null, optional) Filter by malware count (for items not equal to the given value)
  - `malware_count__gt` (integer | null, optional) Filter by malware count (for items greater than the given value)
  - `malware_count__gte` (integer | null, optional) Filter by malware count (for items greater than or equal to the given value)
  - `malware_count__lt` (integer | null, optional) Filter by malware count (for items less than the given value)
  - `malware_count__lte` (integer | null, optional) Filter by malware count (for items less than or equal to the given value)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/vulnerabilities/exploited`
- `GET`: Exploited Vulnerabilities Index
  Filters/params:
  - `filter` (string, optional) A string used to filter vulnerabilities. It can start with specific prefixes to indicate the type of filter:
- `cve:`: Filter by CVE ID.
- `uuid:`: Filter by UUID.
- `internal_name:`: Filter by internal_name (exact match).
- `desc:`: Filter by description (searches both description and gen_description fields).
- `gen_display_name:`: Filter by gen_display_name.
- `cisa_kev:`: Filter by cisa_kev.
- `state:`: Filter by state.
- `exploitation_begins_at{operator}`: Filter by begins_at.  Allowed operators are: <, <=, =, >=, > (e.g. `exploitation_begins_at>2025-11-01`)
- `exploitation_ends_at{operator}`: Filter by ends_at.  Allowed operators are: <, <=, =, >=, > (e.g. `exploitation_ends_at<2025-11-01`)
- If the filter string matches the pattern `CVE-` or a UUID pattern, it will be treated as a specific filter.
- If no prefix is provided, it defaults to a description filter (searches both description fields).
  - `sort` (string, optional) Field to sort by - either cve_id, gen_cwe_id, state, created_at, updated_at, enriched_at, published_at, cvss_base_score, cvss_version, epss_score, epss_percentile, trending_1d, trending_7d, or trending_30d (pattern: ^(cve_id|gen_cwe_id|state|created_at|updated_at|enriched_at|published_at|cvss_base_score|cvss_version|epss_score|epss_percentile|trending_1d|trending_7d|trending_30d)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `include_merged` (boolean, optional) Include entities that have been merged into other entities (default: False)

### `/v1/vulnerabilities/trending/diff`
- `GET`: Trending Diff Endpoint
  Filters/params:
  - `window` (string, optional) Time window for comparison. Format: '<number><unit>' where unit is 'd' (days) or 'h' (hours). Examples: '1d', '12h', '7d'. Maximum: 30d or 720h. Default: '1d'. (pattern: ^\d+[dh]$; default: 1d)
  - `trending_limit` (integer, optional) Maximum number of entities to consider as 'trending' per period. Only the top N entities by mention count are compared. Default: 10. (min: 1; max: 100; default: 10)

### `/v1/vulnerabilities/{identifier}`
- `GET`: Single Vulnerability

### `/v1/vulnerabilities/{identifier}/configurations`
- `GET`: Single Vulnerability Configurations
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by - created_at, updated_at, vendor, product_name, or product_type (pattern: ^(created_at|updated_at|vendor|product_name|product_type)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'vulnerable:true' or 'vulnerable:false')
  - `type` (string, optional) Output model type (pattern: ^(basic|detailed)$; default: detailed)

### `/v1/vulnerabilities/{identifier}/detection_signatures`
- `GET`: Single Vulnerability Detection Signatures
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|source|method|upstream_id)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'method:snort')
  - `type` (string, optional) Output model type (pattern: ^(basic|detailed)$; default: basic)

### `/v1/vulnerabilities/{identifier}/enrich`
- `POST`: Enrich Vulnerability

### `/v1/vulnerabilities/{identifier}/exploitations`
- `GET`: Single Vulnerability Exploitations
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|begins_at|ends_at|count)$; default: begins_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `type` (string, optional) Output model type (pattern: ^(basic|detailed)$; default: detailed)

### `/v1/vulnerabilities/{identifier}/exploits`
- `GET`: Single Vulnerability Exploits
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|disclosed_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'maturity:functional')
  - `type` (string, optional) Output model type (pattern: ^(basic|detailed)$; default: basic)

### `/v1/vulnerabilities/{identifier}/export`
- `GET`: Export Vulnerability
  Filters/params:
  - `relationships_created_after` (string | null, optional) Filter related objects to only include those created after this ISO8601/RFC3339 timestamp
  - `relationships_created_before` (string | null, optional) Filter related objects to only include those created before this ISO8601/RFC3339 timestamp

### `/v1/vulnerabilities/{identifier}/mentions`
- `GET`: Single Vulnerability Mentions
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 1000; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(created_at|updated_at|published_at|source)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'user_generated_content:true' or 'user_generated_content:false')

### `/v1/vulnerabilities/{identifier}/observables`
- `GET`: Single Vulnerability Observables
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(type|name|created_at|published_at)$; default: published_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)
  - `filter` (string, optional) Filter parameter (e.g., 'type:ip.v4', 'type:domain', 'type:hash.sha256')

### `/v1/vulnerabilities/{identifier}/products`
- `GET`: Single Vulnerability Products

### `/v1/vulnerabilities/{identifier}/technology_product_advisories`
- `GET`: Single Vulnerability Technology Product Advisories

### `/v1/vulnerabilities/{identifier}/used_by_malware`
- `GET`: Single Vulnerability Used By Malware
  Filters/params:
  - `offset` (integer, optional) Number of items to skip (min: 0; default: 0)
  - `limit` (integer, optional) Maximum number of items to return (min: 1; max: 500; default: 100)
  - `sort` (string, optional) Field to sort by (pattern: ^(name|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order (pattern: ^(asc|desc)$; default: desc)

### `/v1/vulnerable_technology_product_configuration_sets`
- `GET`: Vulnerable Technology Product Configuration Set Index
  Filters/params:
  - `filter` (string, optional) A string used to filter configuration sets. It can start with specific prefixes to indicate the type of filter:
- `set_id:`: Filter by set_id.
- `vulnerability_uuid:`: Filter by vulnerability_uuid.
- `configuration_uuid:`: Filter by technology_product_configuration_uuid.
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either set_id, created_at or updated_at (pattern: ^(set_id|created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/vulnerable_technology_product_configuration_sets/by-configuration/{configuration_uuid}`
- `GET`: Get By Configuration

### `/v1/vulnerable_technology_product_configuration_sets/by-vulnerability/{vulnerability_uuid}`
- `GET`: Get By Vulnerability

### `/v1/vulnerable_technology_product_configuration_sets/search`
- `POST`: Vulnerable Technology Product Configuration Set Search
  Filters/params:
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either created_at or updated_at (pattern: ^(created_at|updated_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)

### `/v1/vulnerable_technology_product_configuration_sets/{identifier}`
- `GET`: Lookup Vulnerable Technology Product Configuration Set

### `/v1/weaknesses`
- `GET`: Weakness Index
  Filters/params:
  - `filter` (string, optional) Filter the weaknesses by name (default: )
  - `offset` (integer, optional) The number of items to skip before starting to collect the result set. (min: 0; default: 0)
  - `limit` (integer, optional) The maximum number of items to return. (min: 1; default: 100)
  - `sort` (string, optional) Field to sort by - either name, created_at or updated_at (pattern: ^(name|created_at|updated_at|enriched_at)$; default: created_at)
  - `order` (string, optional) Sort order - either asc or desc (pattern: ^(asc|desc)$; default: desc)
  - `created_at__gte` (string | null, optional) Filter on the created_at field for items greater than or equal to the given value
  - `created_at__lt` (string | null, optional) Filter on the created_at field for items less than the given value
  - `updated_at__gte` (string | null, optional) Filter on the updated_at field for items greater than or equal to the given value
  - `updated_at__lt` (string | null, optional) Filter on the updated_at field for items less than the given value

### `/v1/weaknesses/{identifier}`
- `GET`: Lookup Weakness
