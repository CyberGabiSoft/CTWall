-- CTWall baseline schema migration
-- Fresh schema-only init generated from current final database state.
-- Backward compatibility migration steps were intentionally removed.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
SET check_function_bodies = false;

-- Name: ctwall_product_group_grants_validate(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.ctwall_product_group_grants_validate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    product_project_id UUID;
    owner_group_id UUID;
    group_project_id UUID;
BEGIN
    SELECT p.project_id, p.owner_group_id
    INTO product_project_id, owner_group_id
    FROM products p
    WHERE p.id = NEW.product_id;

    IF product_project_id IS NULL THEN
        RAISE EXCEPTION 'Product not found'
            USING ERRCODE = '23503';
    END IF;

    SELECT ug.project_id
    INTO group_project_id
    FROM user_groups ug
    WHERE ug.id = NEW.group_id;

    IF group_project_id IS NULL THEN
        RAISE EXCEPTION 'Group not found'
            USING ERRCODE = '23503';
    END IF;
    IF group_project_id <> product_project_id THEN
        RAISE EXCEPTION 'Grant group must belong to the same project as product'
            USING ERRCODE = '23514';
    END IF;
    IF owner_group_id IS NOT NULL AND NEW.group_id = owner_group_id THEN
        RAISE EXCEPTION 'Owner group is implicit and cannot be inserted into product_group_grants'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: ctwall_products_validate_owner_group(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.ctwall_products_validate_owner_group() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    owner_project_id UUID;
BEGIN
    IF NEW.owner_group_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT ug.project_id
    INTO owner_project_id
    FROM user_groups ug
    WHERE ug.id = NEW.owner_group_id;

    IF owner_project_id IS NULL THEN
        RAISE EXCEPTION 'Owner group not found'
            USING ERRCODE = '23503';
    END IF;
    IF owner_project_id <> NEW.project_id THEN
        RAISE EXCEPTION 'Owner group must belong to the same project as product'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.created_by IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
           FROM user_group_members gm
           WHERE gm.group_id = NEW.owner_group_id
             AND gm.user_id = NEW.created_by
             AND gm.role = 'OWNER'
       ) THEN
        RAISE EXCEPTION 'Product creator must be OWNER in owner group'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;


--
--
-- Name: alert_connector_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_connector_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    connector_type text NOT NULL,
    is_enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    jira_dedup_rule_id uuid,
    CONSTRAINT alert_connector_settings_connector_type_check CHECK ((connector_type = ANY (ARRAY['DISCORD'::text, 'SMTP'::text, 'MSTEAMSV2'::text, 'JIRA'::text, 'ALERTMANAGER_EXTERNAL'::text, 'OPSGENIE'::text, 'PAGERDUTY'::text, 'PUSHOVER'::text, 'ROCKETCHAT'::text, 'SLACK'::text, 'SNS'::text, 'TELEGRAM'::text, 'VICTOROPS'::text, 'WEBEX'::text, 'WEBHOOK'::text, 'WECHAT'::text])))
);


--
-- Name: alert_dedup_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_dedup_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    alert_type text NOT NULL,
    dedup_scope text NOT NULL,
    product_id uuid,
    scope_id uuid,
    test_id uuid,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    min_severity text DEFAULT 'INFO'::text NOT NULL,
    CONSTRAINT alert_dedup_rules_dedup_scope_check CHECK ((dedup_scope = ANY (ARRAY['GLOBAL'::text, 'PRODUCT'::text, 'SCOPE'::text, 'TEST'::text]))),
    CONSTRAINT alert_dedup_rules_min_severity_check CHECK ((min_severity = ANY (ARRAY['INFO'::text, 'WARNING'::text, 'ERROR'::text]))),
    CONSTRAINT chk_alert_dedup_rules_scope_target CHECK ((((dedup_scope = 'GLOBAL'::text) AND (product_id IS NULL) AND (scope_id IS NULL) AND (test_id IS NULL)) OR ((dedup_scope = 'PRODUCT'::text) AND (product_id IS NOT NULL) AND (scope_id IS NULL) AND (test_id IS NULL)) OR ((dedup_scope = 'SCOPE'::text) AND (product_id IS NULL) AND (scope_id IS NOT NULL) AND (test_id IS NULL)) OR ((dedup_scope = 'TEST'::text) AND (product_id IS NULL) AND (scope_id IS NULL) AND (test_id IS NOT NULL))))
);


--
-- Name: alert_detection_modes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_detection_modes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    mode text NOT NULL,
    enabled boolean NOT NULL,
    severity text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_detection_modes_mode_check CHECK ((mode = ANY (ARRAY['PURL_VERSION_SMART'::text, 'PURL_CONTAINS_PREFIX'::text]))),
    CONSTRAINT alert_detection_modes_severity_check CHECK ((severity = ANY (ARRAY['INFO'::text, 'WARN'::text, 'ERROR'::text])))
);


--
-- Name: alert_dispatch_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_dispatch_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    message_type text NOT NULL,
    event_state text,
    project_id uuid,
    group_id uuid,
    payload_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    state text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    locked_at timestamp with time zone,
    locked_by text,
    last_error_code text,
    last_error_message text,
    done_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_dispatch_queue_event_state_check CHECK ((event_state = ANY (ARRAY['FIRING'::text, 'RESOLVED'::text]))),
    CONSTRAINT alert_dispatch_queue_message_type_check CHECK ((message_type = ANY (ARRAY['CONFIG_APPLY'::text, 'ALERT_EVENT'::text]))),
    CONSTRAINT alert_dispatch_queue_state_check CHECK ((state = ANY (ARRAY['PENDING'::text, 'IN_FLIGHT'::text, 'RETRY'::text, 'DONE'::text, 'DEAD'::text]))),
    CONSTRAINT chk_alert_dispatch_event_fields CHECK ((((message_type = 'ALERT_EVENT'::text) AND (event_state IS NOT NULL) AND (project_id IS NOT NULL) AND (group_id IS NOT NULL)) OR ((message_type = 'CONFIG_APPLY'::text) AND (event_state IS NULL))))
);


--
-- Name: alert_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    severity text NOT NULL,
    category text NOT NULL,
    type text NOT NULL,
    status text NOT NULL,
    group_key text NOT NULL,
    title text NOT NULL,
    entity_ref text,
    occurrences integer DEFAULT 1 NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_notified_at timestamp with time zone,
    acknowledged_at timestamp with time zone,
    acknowledged_by uuid,
    closed_at timestamp with time zone,
    closed_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_groups_severity_check CHECK ((severity = ANY (ARRAY['INFO'::text, 'WARN'::text, 'ERROR'::text]))),
    CONSTRAINT alert_groups_status_check CHECK ((status = ANY (ARRAY['OPEN'::text, 'ACKNOWLEDGED'::text, 'CLOSED'::text])))
);


--
-- Name: alert_occurrences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_occurrences (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    group_id uuid NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    product_id uuid,
    scope_id uuid,
    test_id uuid,
    entity_ref text,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: alert_routes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_routes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    connector_type text NOT NULL,
    target_type text NOT NULL,
    target_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_routes_connector_type_check CHECK ((connector_type = ANY (ARRAY['DISCORD'::text, 'SMTP'::text, 'MSTEAMSV2'::text, 'JIRA'::text, 'ALERTMANAGER_EXTERNAL'::text, 'OPSGENIE'::text, 'PAGERDUTY'::text, 'PUSHOVER'::text, 'ROCKETCHAT'::text, 'SLACK'::text, 'SNS'::text, 'TELEGRAM'::text, 'VICTOROPS'::text, 'WEBEX'::text, 'WEBHOOK'::text, 'WECHAT'::text]))),
    CONSTRAINT alert_routes_target_type_check CHECK ((target_type = ANY (ARRAY['PRODUCT'::text, 'SCOPE'::text, 'TEST'::text])))
);


--
-- Name: api_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    token_hash text NOT NULL,
    last_used_at timestamp with time zone,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    entity_type text NOT NULL,
    entity_id uuid,
    details jsonb,
    ip_address text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: component_analysis_malware_component_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_analysis_malware_component_state (
    component_purl text CONSTRAINT component_analysis_malware_component_st_component_purl_not_null NOT NULL,
    scanned_at timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE component_analysis_malware_component_state; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.component_analysis_malware_component_state IS 'Tracks the latest component malware mapping run per component PURL (even if no findings).';


--
-- Name: component_analysis_malware_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_analysis_malware_findings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_purl text NOT NULL,
    malware_purl text NOT NULL,
    source_malware_input_result_id uuid CONSTRAINT component_analysis_malware__source_malware_input_resul_not_null NOT NULL,
    match_type text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_analysis_malware_findings_match_type_check CHECK ((match_type = ANY (ARRAY['EXACT'::text, 'CONTAINS_PREFIX'::text])))
);


--
-- Name: TABLE component_analysis_malware_findings; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.component_analysis_malware_findings IS 'Mapping between SBOM component PURLs and malware input PURLs.';


--
-- Name: component_analysis_malware_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_analysis_malware_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_purl text NOT NULL,
    status text DEFAULT 'PENDING'::text NOT NULL,
    reason text DEFAULT 'SCHEDULED'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    locked_at timestamp with time zone,
    locked_by text,
    scheduled_for timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT component_analysis_malware_queue_reason_check CHECK ((reason = ANY (ARRAY['SCHEDULED'::text, 'MANUAL'::text, 'BACKFILL'::text]))),
    CONSTRAINT component_analysis_malware_queue_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text, 'COMPLETED'::text, 'FAILED'::text])))
);


--
-- Name: TABLE component_analysis_malware_queue; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.component_analysis_malware_queue IS 'Queue of component PURL mapping runs to malware input results.';


--
-- Name: component_analysis_malware_schedule; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_analysis_malware_schedule (
    id integer NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    interval_seconds integer DEFAULT 21600 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_analysis_malware_schedule_id_check CHECK ((id = 1)),
    CONSTRAINT component_analysis_malware_schedule_interval_seconds_check CHECK ((interval_seconds >= 0))
);


--
-- Name: TABLE component_analysis_malware_schedule; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.component_analysis_malware_schedule IS 'Runtime configuration for scheduled component malware mapping re-analysis.';


--
-- Name: component_malware_findings_triage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_malware_findings_triage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    test_id uuid NOT NULL,
    component_purl text NOT NULL,
    malware_purl text NOT NULL,
    status text NOT NULL,
    priority text,
    reason text,
    expires_at timestamp with time zone,
    author_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_component_malware_findings_triage_status CHECK ((status = ANY (ARRAY['OPEN'::text, 'RISK_ACCEPTED'::text, 'FALSE_POSITIVE'::text, 'FIXED'::text]))),
    CONSTRAINT component_malware_findings_triage_priority_check CHECK ((priority = ANY (ARRAY['P1'::text, 'P2'::text, 'P3'::text, 'P4'::text])))
);


--
-- Name: component_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_overrides (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    test_id uuid NOT NULL,
    purl_pattern text NOT NULL,
    status text NOT NULL,
    reason text,
    comment text,
    author_id uuid,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT component_overrides_status_check CHECK ((status = ANY (ARRAY['APPROVED'::text, 'WARNING'::text, 'REJECTED'::text])))
);


--
-- Name: TABLE component_overrides; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.component_overrides IS 'Stores triage decisions (Approved/Rejected) that persist across SBOM uploads for a Test.';


--
-- Name: components; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.components (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    revision_id uuid NOT NULL,
    purl text NOT NULL,
    pkg_name text NOT NULL,
    version text NOT NULL,
    pkg_type text NOT NULL,
    pkg_namespace text,
    sbom_type text NOT NULL,
    publisher text,
    supplier text,
    licenses jsonb DEFAULT '[]'::jsonb,
    properties jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: connector_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connector_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    connector_type text NOT NULL,
    scope_type text DEFAULT 'GLOBAL'::text NOT NULL,
    scope_id uuid,
    config_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_enabled boolean DEFAULT false NOT NULL,
    last_test_status text DEFAULT 'NOT_CONFIGURED'::text NOT NULL,
    last_test_at timestamp with time zone,
    last_test_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    config_schema_version integer DEFAULT 1 NOT NULL,
    CONSTRAINT chk_connector_scope_ref CHECK ((((scope_type = 'GLOBAL'::text) AND (scope_id IS NULL)) OR ((scope_type <> 'GLOBAL'::text) AND (scope_id IS NOT NULL)))),
    CONSTRAINT connector_configs_connector_type_check CHECK ((connector_type = ANY (ARRAY['DISCORD'::text, 'SMTP'::text, 'MSTEAMSV2'::text, 'JIRA'::text, 'ALERTMANAGER_EXTERNAL'::text, 'OPSGENIE'::text, 'PAGERDUTY'::text, 'PUSHOVER'::text, 'ROCKETCHAT'::text, 'SLACK'::text, 'SNS'::text, 'TELEGRAM'::text, 'VICTOROPS'::text, 'WEBEX'::text, 'WEBHOOK'::text, 'WECHAT'::text]))),
    CONSTRAINT connector_configs_last_test_status_check CHECK ((last_test_status = ANY (ARRAY['NOT_CONFIGURED'::text, 'PASSED'::text, 'FAILED'::text]))),
    CONSTRAINT connector_configs_scope_type_check CHECK ((scope_type = ANY (ARRAY['GLOBAL'::text, 'PROJECT'::text, 'PRODUCT'::text, 'SCOPE'::text, 'TEST'::text])))
);


--
-- Name: ingest_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingest_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    product_id uuid,
    scope_id uuid,
    test_id uuid,
    sbom_sha256 character(64) NOT NULL,
    sbom_standard text NOT NULL,
    sbom_spec_version text DEFAULT 'unknown'::text NOT NULL,
    sbom_producer text DEFAULT 'other'::text NOT NULL,
    tags jsonb DEFAULT '[]'::jsonb NOT NULL,
    metadata_json jsonb,
    content_type text DEFAULT ''::text NOT NULL,
    is_gzip boolean DEFAULT false NOT NULL,
    components_count integer DEFAULT 0 NOT NULL,
    processing_stage text DEFAULT 'RECEIVED'::text NOT NULL,
    status text NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT ingest_queue_processing_stage_check CHECK ((processing_stage = ANY (ARRAY['RECEIVED'::text, 'VALIDATING'::text, 'PARSING'::text, 'ANALYZING'::text, 'STORING'::text, 'REVISIONING'::text, 'COMPLETED'::text, 'FAILED'::text]))),
    CONSTRAINT ingest_queue_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text, 'COMPLETED'::text, 'FAILED'::text])))
);


--
-- Name: TABLE ingest_queue; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.ingest_queue IS 'Durable ingest buffer for SBOM uploads and retry.';


--
-- Name: jira_delivery_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jira_delivery_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    queue_job_id uuid,
    project_id uuid NOT NULL,
    config_level text,
    config_target_id uuid,
    alert_group_id uuid,
    dedup_rule_id uuid,
    jira_issue_mapping_id uuid,
    attempt_no integer DEFAULT 1 NOT NULL,
    action text NOT NULL,
    outcome text NOT NULL,
    http_status integer,
    error_code text,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT jira_delivery_attempts_action_check CHECK ((action = ANY (ARRAY['CREATE'::text, 'UPDATE'::text, 'REOPEN'::text, 'RESOLVE'::text, 'SUPERSEDE_CLOSE'::text, 'NOOP'::text]))),
    CONSTRAINT jira_delivery_attempts_config_level_check CHECK ((config_level = ANY (ARRAY['PRODUCT'::text, 'SCOPE'::text, 'TEST'::text]))),
    CONSTRAINT jira_delivery_attempts_outcome_check CHECK ((outcome = ANY (ARRAY['SUCCESS'::text, 'RETRY'::text, 'DEAD'::text, 'SKIPPED'::text, 'FAILED'::text])))
);


--
-- Name: jira_entity_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jira_entity_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    config_level text NOT NULL,
    config_target_id uuid NOT NULL,
    is_enabled boolean DEFAULT false NOT NULL,
    jira_project_key text DEFAULT ''::text NOT NULL,
    issue_type text DEFAULT ''::text NOT NULL,
    resolve_transition_name text,
    labels jsonb DEFAULT '[]'::jsonb NOT NULL,
    components jsonb DEFAULT '[]'::jsonb NOT NULL,
    severity_to_priority_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    ticket_summary_template text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    open_transition_name text,
    issue_fields_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    delivery_retry_attempts integer DEFAULT 0 NOT NULL,
    delivery_retry_backoff_seconds integer DEFAULT 10 NOT NULL,
    CONSTRAINT chk_jira_entity_settings_components_array CHECK ((jsonb_typeof(components) = 'array'::text)),
    CONSTRAINT chk_jira_entity_settings_delivery_retry_attempts_range CHECK (((delivery_retry_attempts >= 0) AND (delivery_retry_attempts <= 20))),
    CONSTRAINT chk_jira_entity_settings_delivery_retry_backoff_range CHECK (((delivery_retry_backoff_seconds >= 1) AND (delivery_retry_backoff_seconds <= 3600))),
    CONSTRAINT chk_jira_entity_settings_issue_fields_object CHECK ((jsonb_typeof(issue_fields_json) = 'object'::text)),
    CONSTRAINT chk_jira_entity_settings_labels_array CHECK ((jsonb_typeof(labels) = 'array'::text)),
    CONSTRAINT chk_jira_entity_settings_priority_object CHECK ((jsonb_typeof(severity_to_priority_mapping) = 'object'::text)),
    CONSTRAINT jira_entity_settings_config_level_check CHECK ((config_level = ANY (ARRAY['PRODUCT'::text, 'SCOPE'::text, 'TEST'::text])))
);


--
-- Name: jira_issue_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jira_issue_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    config_level text NOT NULL,
    config_target_id uuid NOT NULL,
    alert_group_id uuid NOT NULL,
    dedup_rule_id uuid,
    jira_issue_key text,
    jira_issue_id text,
    status text NOT NULL,
    last_synced_at timestamp with time zone,
    last_error text,
    closed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    test_id uuid,
    component_purl text,
    effective_config_level text,
    effective_config_target_id uuid,
    CONSTRAINT jira_issue_mappings_config_level_check CHECK ((config_level = ANY (ARRAY['PRODUCT'::text, 'SCOPE'::text, 'TEST'::text]))),
    CONSTRAINT jira_issue_mappings_effective_config_level_check CHECK (((effective_config_level IS NULL) OR (effective_config_level = ANY (ARRAY['PRODUCT'::text, 'SCOPE'::text, 'TEST'::text])))),
    CONSTRAINT jira_issue_mappings_status_check CHECK ((status = ANY (ARRAY['OPEN'::text, 'CLOSED'::text, 'DEAD'::text, 'SUPERSEDED'::text])))
);


--
-- Name: jira_metadata_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jira_metadata_cache (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    base_url_hash text NOT NULL,
    metadata_type text NOT NULL,
    metadata_scope_key text DEFAULT ''::text NOT NULL,
    payload_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT jira_metadata_cache_metadata_type_check CHECK ((metadata_type = ANY (ARRAY['PROJECTS'::text, 'ISSUE_TYPES'::text, 'COMPONENTS'::text, 'PRIORITIES'::text, 'ISSUES'::text, 'TRANSITIONS'::text, 'ISSUE_FIELDS'::text])))
);


--
-- Name: product_group_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.product_group_grants (
    product_id uuid NOT NULL,
    group_id uuid NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    CONSTRAINT product_group_grants_role_check CHECK ((role = ANY (ARRAY['EDITOR'::text, 'VIEWER'::text])))
);


--
-- Name: products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.products (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    archived_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    project_id uuid NOT NULL,
    malware_default_priority text,
    owner_group_id uuid,
    created_by uuid,
    CONSTRAINT chk_products_malware_default_priority CHECK (((malware_default_priority IS NULL) OR (malware_default_priority = ANY (ARRAY['P1'::text, 'P2'::text, 'P3'::text, 'P4'::text]))))
);


--
-- Name: TABLE products; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.products IS 'Root entity for organizing projects (e.g. "Banking Ecosystem").';


--
-- Name: project_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_memberships (
    project_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    project_role text DEFAULT 'READER'::text NOT NULL,
    CONSTRAINT chk_project_memberships_project_role CHECK ((project_role = ANY (ARRAY['ADMIN'::text, 'WRITER'::text, 'READER'::text])))
);


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    archived_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    replaced_by_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    last_used_at timestamp with time zone,
    user_agent text,
    ip_address text
);


--
-- Name: sbom_objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_objects (
    sha256 character(64) NOT NULL,
    storage_path text NOT NULL,
    size_bytes bigint NOT NULL,
    format text NOT NULL,
    content_type text DEFAULT ''::text NOT NULL,
    is_gzip boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE sbom_objects; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.sbom_objects IS 'Physical file storage metadata. Content is deduplicated by SHA256.';


--
-- Name: scan_malware_source; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scan_malware_source (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    source_type text NOT NULL,
    base_url text NOT NULL,
    config_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT scan_malware_source_source_type_check CHECK ((source_type = ANY (ARRAY['OSV_API'::text, 'OSV_MIRROR'::text, 'GITHUB_ADVISORIES'::text])))
);


--
-- Name: TABLE scan_malware_source; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.scan_malware_source IS 'Configuration for malware data sources (OSV API/mirror, GitHub advisories, etc.).';


--
-- Name: scopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scopes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    product_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    archived_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    malware_default_priority text,
    CONSTRAINT chk_scopes_malware_default_priority CHECK (((malware_default_priority IS NULL) OR (malware_default_priority = ANY (ARRAY['P1'::text, 'P2'::text, 'P3'::text, 'P4'::text]))))
);


--
-- Name: TABLE scopes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.scopes IS 'Sub-grouping within Product (e.g. "Backend Team" or "Payments Module").';


--
-- Name: source_malware_input_component_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_malware_input_component_results (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_purl text NOT NULL,
    component_hash text,
    analysis_result_id uuid,
    scan_id uuid NOT NULL,
    source_id uuid NOT NULL,
    result_filename text,
    evidence text,
    details_json jsonb NOT NULL,
    published_at timestamp with time zone,
    modified_at timestamp with time zone,
    detect_version text,
    fixed_version text,
    is_malware boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE source_malware_input_component_results; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.source_malware_input_component_results IS 'Raw malware/heuristics findings per component PURL (hash may be unavailable).';


--
-- Name: source_malware_input_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_malware_input_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_purl text NOT NULL,
    scanner_id uuid NOT NULL,
    status text DEFAULT 'PENDING'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT source_malware_input_queue_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text, 'COMPLETED'::text, 'FAILED'::text])))
);


--
-- Name: source_malware_input_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_malware_input_results (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_purl text NOT NULL,
    component_hash text,
    verdict text NOT NULL,
    findings_count integer DEFAULT 0,
    summary text,
    scanned_at timestamp with time zone DEFAULT now(),
    valid_until timestamp with time zone,
    CONSTRAINT source_malware_input_results_verdict_check CHECK ((verdict = ANY (ARRAY['MALWARE'::text, 'CLEAN'::text, 'UNKNOWN'::text])))
);


--
-- Name: TABLE source_malware_input_results; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.source_malware_input_results IS 'Persistent storage for analysis results (Malware/Heuristics). Decoupled from specific SBOMs via PURL.';


--
-- Name: source_scanners; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_scanners (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid NOT NULL,
    name text NOT NULL,
    scanner_type text NOT NULL,
    version text,
    results_path text,
    config_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE source_scanners; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.source_scanners IS 'Registered scanners with type/name/version tied to a malware source.';


--
-- Name: test_revision_change_summary; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_revision_change_summary (
    to_revision_id uuid NOT NULL,
    project_id uuid NOT NULL,
    test_id uuid NOT NULL,
    from_revision_id uuid,
    added_count integer DEFAULT 0 NOT NULL,
    removed_count integer DEFAULT 0 NOT NULL,
    unchanged_count integer DEFAULT 0 NOT NULL,
    reappeared_count integer DEFAULT 0 NOT NULL,
    status text NOT NULL,
    computed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT test_revision_change_summary_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text, 'COMPLETED'::text, 'FAILED'::text])))
);


--
-- Name: test_revision_finding_diff_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_revision_finding_diff_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    test_id uuid NOT NULL,
    from_revision_id uuid,
    to_revision_id uuid NOT NULL,
    status text NOT NULL,
    reason text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    locked_at timestamp with time zone,
    locked_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT test_revision_finding_diff_queue_reason_check CHECK ((reason = ANY (ARRAY['INGEST'::text, 'BACKFILL'::text, 'MANUAL'::text]))),
    CONSTRAINT test_revision_finding_diff_queue_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text, 'COMPLETED'::text, 'FAILED'::text])))
);


--
-- Name: test_revision_finding_diffs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_revision_finding_diffs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    test_id uuid NOT NULL,
    from_revision_id uuid,
    to_revision_id uuid NOT NULL,
    finding_type text NOT NULL,
    diff_type text NOT NULL,
    component_purl text NOT NULL,
    malware_purl text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT test_revision_finding_diffs_diff_type_check CHECK ((diff_type = ANY (ARRAY['ADDED'::text, 'REMOVED'::text, 'UNCHANGED'::text, 'REAPPEARED'::text]))),
    CONSTRAINT test_revision_finding_diffs_finding_type_check CHECK ((finding_type = 'MALWARE'::text))
);


--
-- Name: test_revision_malware_summary; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_revision_malware_summary (
    revision_id uuid NOT NULL,
    malware_component_count integer DEFAULT 0 NOT NULL,
    computed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT test_revision_malware_summary_malware_component_count_check CHECK ((malware_component_count >= 0))
);


--
-- Name: TABLE test_revision_malware_summary; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.test_revision_malware_summary IS 'Materialized malware summary per TestRevision. Source of truth remains mappings/results; this is a cached read model.';


--
-- Name: test_revision_malware_summary_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_revision_malware_summary_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    revision_id uuid NOT NULL,
    status text DEFAULT 'PENDING'::text NOT NULL,
    reason text DEFAULT 'BACKFILL'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    locked_at timestamp with time zone,
    locked_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT test_revision_malware_summary_queue_reason_check CHECK ((reason = ANY (ARRAY['BACKFILL'::text, 'INGEST'::text, 'COMPONENT_ANALYSIS_UPDATE'::text, 'MANUAL'::text]))),
    CONSTRAINT test_revision_malware_summary_queue_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text, 'COMPLETED'::text, 'FAILED'::text])))
);


--
-- Name: TABLE test_revision_malware_summary_queue; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.test_revision_malware_summary_queue IS 'Queue of recomputation jobs for test_revision_malware_summary.';


--
-- Name: test_revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_revisions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    test_id uuid NOT NULL,
    sbom_sha256 character(64) NOT NULL,
    sbom_producer text DEFAULT 'other'::text NOT NULL,
    sbom_metadata_json jsonb,
    is_active boolean DEFAULT true,
    components_count integer DEFAULT 0,
    tags jsonb DEFAULT '[]'::jsonb NOT NULL,
    metadata_json jsonb,
    last_modified_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE test_revisions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.test_revisions IS 'Immutable snapshot of an uploaded SBOM file linked to a Test.';


--
-- Name: tests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    scope_id uuid NOT NULL,
    name text NOT NULL,
    is_public boolean DEFAULT false NOT NULL,
    public_token text,
    archived_at timestamp with time zone,
    sbom_standard text NOT NULL,
    sbom_spec_version text DEFAULT 'unknown'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    malware_default_priority text,
    CONSTRAINT chk_tests_malware_default_priority CHECK (((malware_default_priority IS NULL) OR (malware_default_priority = ANY (ARRAY['P1'::text, 'P2'::text, 'P3'::text, 'P4'::text]))))
);


--
-- Name: TABLE tests; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tests IS 'Logical representation of an Application/Service. Holds configuration and permissions, effectively a container for SBOM history.';


--
-- Name: user_group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_group_members (
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    CONSTRAINT user_group_members_role_check CHECK ((role = ANY (ARRAY['OWNER'::text, 'EDITOR'::text, 'VIEWER'::text])))
);


--
-- Name: user_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid
);


--
-- Name: user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_settings (
    user_id uuid NOT NULL,
    selected_project_id uuid,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    role text DEFAULT 'NONE'::text,
    account_type text DEFAULT 'USER'::text,
    full_name text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    nickname text DEFAULT 'user'::text NOT NULL,
    CONSTRAINT chk_users_nickname CHECK (((char_length(btrim(nickname)) >= 1) AND (char_length(btrim(nickname)) <= 64))),
    CONSTRAINT chk_users_role CHECK ((role = ANY (ARRAY['ADMIN'::text, 'WRITER'::text, 'READER'::text, 'NONE'::text]))),
    CONSTRAINT users_account_type_check CHECK ((account_type = ANY (ARRAY['USER'::text, 'SERVICE_ACCOUNT'::text])))
);


--
-- Name: alert_connector_settings alert_connector_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_connector_settings
    ADD CONSTRAINT alert_connector_settings_pkey PRIMARY KEY (id);


--
-- Name: alert_connector_settings alert_connector_settings_project_id_connector_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_connector_settings
    ADD CONSTRAINT alert_connector_settings_project_id_connector_type_key UNIQUE (project_id, connector_type);


--
-- Name: alert_dedup_rules alert_dedup_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dedup_rules
    ADD CONSTRAINT alert_dedup_rules_pkey PRIMARY KEY (id);


--
-- Name: alert_detection_modes alert_detection_modes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_detection_modes
    ADD CONSTRAINT alert_detection_modes_pkey PRIMARY KEY (id);


--
-- Name: alert_dispatch_queue alert_dispatch_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dispatch_queue
    ADD CONSTRAINT alert_dispatch_queue_pkey PRIMARY KEY (id);


--
-- Name: alert_groups alert_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_pkey PRIMARY KEY (id);


--
-- Name: alert_groups alert_groups_project_id_group_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_project_id_group_key_key UNIQUE (project_id, group_key);


--
-- Name: alert_occurrences alert_occurrences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_pkey PRIMARY KEY (id);


--
-- Name: alert_routes alert_routes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_routes
    ADD CONSTRAINT alert_routes_pkey PRIMARY KEY (id);


--
-- Name: alert_routes alert_routes_project_id_connector_type_target_type_target_i_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_routes
    ADD CONSTRAINT alert_routes_project_id_connector_type_target_type_target_i_key UNIQUE (project_id, connector_type, target_type, target_id);


--
-- Name: api_tokens api_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: component_analysis_malware_component_state component_analysis_malware_component_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_analysis_malware_component_state
    ADD CONSTRAINT component_analysis_malware_component_state_pkey PRIMARY KEY (component_purl);


--
-- Name: component_analysis_malware_findings component_analysis_malware_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_analysis_malware_findings
    ADD CONSTRAINT component_analysis_malware_findings_pkey PRIMARY KEY (id);


--
-- Name: component_analysis_malware_queue component_analysis_malware_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_analysis_malware_queue
    ADD CONSTRAINT component_analysis_malware_queue_pkey PRIMARY KEY (id);


--
-- Name: component_analysis_malware_schedule component_analysis_malware_schedule_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_analysis_malware_schedule
    ADD CONSTRAINT component_analysis_malware_schedule_pkey PRIMARY KEY (id);


--
-- Name: component_malware_findings_triage component_malware_findings_triage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_malware_findings_triage
    ADD CONSTRAINT component_malware_findings_triage_pkey PRIMARY KEY (id);


--
-- Name: component_overrides component_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_overrides
    ADD CONSTRAINT component_overrides_pkey PRIMARY KEY (id);


--
-- Name: components components_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.components
    ADD CONSTRAINT components_pkey PRIMARY KEY (id);


--
-- Name: connector_configs connector_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connector_configs
    ADD CONSTRAINT connector_configs_pkey PRIMARY KEY (id);


--
-- Name: ingest_queue ingest_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_queue
    ADD CONSTRAINT ingest_queue_pkey PRIMARY KEY (id);


--
-- Name: jira_delivery_attempts jira_delivery_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_delivery_attempts
    ADD CONSTRAINT jira_delivery_attempts_pkey PRIMARY KEY (id);


--
-- Name: jira_entity_settings jira_entity_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_entity_settings
    ADD CONSTRAINT jira_entity_settings_pkey PRIMARY KEY (id);


--
-- Name: jira_entity_settings jira_entity_settings_project_id_config_level_config_target__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_entity_settings
    ADD CONSTRAINT jira_entity_settings_project_id_config_level_config_target__key UNIQUE (project_id, config_level, config_target_id);


--
-- Name: jira_issue_mappings jira_issue_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_issue_mappings
    ADD CONSTRAINT jira_issue_mappings_pkey PRIMARY KEY (id);


--
-- Name: jira_metadata_cache jira_metadata_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_metadata_cache
    ADD CONSTRAINT jira_metadata_cache_pkey PRIMARY KEY (id);


--
-- Name: jira_metadata_cache jira_metadata_cache_project_id_base_url_hash_metadata_type__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_metadata_cache
    ADD CONSTRAINT jira_metadata_cache_project_id_base_url_hash_metadata_type__key UNIQUE (project_id, base_url_hash, metadata_type, metadata_scope_key);


--
-- Name: product_group_grants product_group_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.product_group_grants
    ADD CONSTRAINT product_group_grants_pkey PRIMARY KEY (product_id, group_id);


--
-- Name: products products_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);


--
-- Name: project_memberships project_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_memberships
    ADD CONSTRAINT project_memberships_pkey PRIMARY KEY (project_id, user_id);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: sbom_objects sbom_objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_objects
    ADD CONSTRAINT sbom_objects_pkey PRIMARY KEY (sha256);


--
-- Name: scan_malware_source scan_malware_source_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scan_malware_source
    ADD CONSTRAINT scan_malware_source_pkey PRIMARY KEY (id);


--
-- Name: scopes scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_pkey PRIMARY KEY (id);


--
-- Name: source_malware_input_component_results source_malware_input_component_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_component_results
    ADD CONSTRAINT source_malware_input_component_results_pkey PRIMARY KEY (id);


--
-- Name: source_malware_input_queue source_malware_input_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_queue
    ADD CONSTRAINT source_malware_input_queue_pkey PRIMARY KEY (id);


--
-- Name: source_malware_input_results source_malware_input_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_results
    ADD CONSTRAINT source_malware_input_results_pkey PRIMARY KEY (id);


--
-- Name: source_scanners source_scanners_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_scanners
    ADD CONSTRAINT source_scanners_pkey PRIMARY KEY (id);


--
-- Name: test_revision_change_summary test_revision_change_summary_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_change_summary
    ADD CONSTRAINT test_revision_change_summary_pkey PRIMARY KEY (to_revision_id);


--
-- Name: test_revision_finding_diff_queue test_revision_finding_diff_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diff_queue
    ADD CONSTRAINT test_revision_finding_diff_queue_pkey PRIMARY KEY (id);


--
-- Name: test_revision_finding_diff_queue test_revision_finding_diff_queue_to_revision_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diff_queue
    ADD CONSTRAINT test_revision_finding_diff_queue_to_revision_id_key UNIQUE (to_revision_id);


--
-- Name: test_revision_finding_diffs test_revision_finding_diffs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diffs
    ADD CONSTRAINT test_revision_finding_diffs_pkey PRIMARY KEY (id);


--
-- Name: test_revision_malware_summary test_revision_malware_summary_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_malware_summary
    ADD CONSTRAINT test_revision_malware_summary_pkey PRIMARY KEY (revision_id);


--
-- Name: test_revision_malware_summary_queue test_revision_malware_summary_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_malware_summary_queue
    ADD CONSTRAINT test_revision_malware_summary_queue_pkey PRIMARY KEY (id);


--
-- Name: test_revisions test_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revisions
    ADD CONSTRAINT test_revisions_pkey PRIMARY KEY (id);


--
-- Name: tests tests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tests
    ADD CONSTRAINT tests_pkey PRIMARY KEY (id);


--
-- Name: alert_detection_modes uq_alert_detection_modes_project_mode; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_detection_modes
    ADD CONSTRAINT uq_alert_detection_modes_project_mode UNIQUE (project_id, mode);


--
-- Name: source_malware_input_queue uq_analysis_queue_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_queue
    ADD CONSTRAINT uq_analysis_queue_target UNIQUE (component_purl, scanner_id);


--
-- Name: component_analysis_malware_findings uq_component_analysis_malware_findings; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_analysis_malware_findings
    ADD CONSTRAINT uq_component_analysis_malware_findings UNIQUE (component_purl, malware_purl);


--
-- Name: component_malware_findings_triage uq_component_malware_findings_triage; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_malware_findings_triage
    ADD CONSTRAINT uq_component_malware_findings_triage UNIQUE (test_id, component_purl, malware_purl);


--
-- Name: component_overrides uq_override_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_overrides
    ADD CONSTRAINT uq_override_target UNIQUE (test_id, purl_pattern);


--
-- Name: source_malware_input_results uq_result_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_results
    ADD CONSTRAINT uq_result_target UNIQUE (component_purl);


--
-- Name: source_malware_input_component_results uq_scan_component_result; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_component_results
    ADD CONSTRAINT uq_scan_component_result UNIQUE (component_purl, source_id, result_filename);


--
-- Name: test_revision_malware_summary_queue uq_test_revision_malware_summary_queue_revision; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_malware_summary_queue
    ADD CONSTRAINT uq_test_revision_malware_summary_queue_revision UNIQUE (revision_id);


--
-- Name: user_group_members user_group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_members
    ADD CONSTRAINT user_group_members_pkey PRIMARY KEY (group_id, user_id);


--
-- Name: user_groups user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (id);


--
-- Name: user_settings user_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_pkey PRIMARY KEY (user_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_alert_connector_settings_jira_dedup_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_connector_settings_jira_dedup_rule ON public.alert_connector_settings USING btree (project_id, connector_type, jira_dedup_rule_id) WHERE (connector_type = 'JIRA'::text);


--
-- Name: idx_alert_dedup_rules_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_dedup_rules_lookup ON public.alert_dedup_rules USING btree (project_id, alert_type, dedup_scope, enabled);


--
-- Name: idx_alert_detection_modes_project_mode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_detection_modes_project_mode ON public.alert_detection_modes USING btree (project_id, mode);


--
-- Name: idx_alert_dispatch_queue_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_dispatch_queue_claim ON public.alert_dispatch_queue USING btree (message_type, state, next_attempt_at, created_at);


--
-- Name: idx_alert_dispatch_queue_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_dispatch_queue_group ON public.alert_dispatch_queue USING btree (project_id, group_id, message_type, created_at DESC) WHERE (group_id IS NOT NULL);


--
-- Name: idx_alert_dispatch_queue_state_done; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_dispatch_queue_state_done ON public.alert_dispatch_queue USING btree (state, done_at);


--
-- Name: idx_alert_groups_project_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_groups_project_last_seen ON public.alert_groups USING btree (project_id, last_seen_at DESC);


--
-- Name: idx_alert_groups_project_status_severity_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_groups_project_status_severity_last_seen ON public.alert_groups USING btree (project_id, status, severity, last_seen_at DESC);


--
-- Name: idx_alert_occurrences_project_group_occurred_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_occurrences_project_group_occurred_at ON public.alert_occurrences USING btree (project_id, group_id, occurred_at DESC);


--
-- Name: idx_alert_occurrences_project_occurred_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_occurrences_project_occurred_at ON public.alert_occurrences USING btree (project_id, occurred_at DESC);


--
-- Name: idx_alert_routes_project_connector; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_routes_project_connector ON public.alert_routes USING btree (project_id, connector_type);


--
-- Name: idx_audit_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_created ON public.audit_logs USING brin (created_at);


--
-- Name: idx_audit_events_ack_event_key_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_ack_event_key_created ON public.audit_logs USING btree (((details ->> 'event_key'::text)), created_at DESC) WHERE ((action = 'EVENT_ACK'::text) AND (details ? 'event_key'::text) AND (COALESCE((details ->> 'event_key'::text), ''::text) <> ''::text));


--
-- Name: idx_audit_events_event_key_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_event_key_created ON public.audit_logs USING btree (((details ->> 'event_key'::text)), created_at DESC) WHERE ((action <> 'EVENT_ACK'::text) AND (details ? 'event_key'::text) AND (COALESCE((details ->> 'event_key'::text), ''::text) <> ''::text));


--
-- Name: idx_audit_events_severity_category_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_severity_category_created ON public.audit_logs USING btree (((details ->> 'severity'::text)), ((details ->> 'category'::text)), created_at DESC) WHERE ((action <> 'EVENT_ACK'::text) AND (details ? 'event_key'::text) AND (COALESCE((details ->> 'event_key'::text), ''::text) <> ''::text));


--
-- Name: idx_component_analysis_malware_component_state_valid_until; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_analysis_malware_component_state_valid_until ON public.component_analysis_malware_component_state USING btree (valid_until);


--
-- Name: idx_component_analysis_malware_findings_component; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_analysis_malware_findings_component ON public.component_analysis_malware_findings USING btree (component_purl);


--
-- Name: idx_component_analysis_malware_findings_malware; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_analysis_malware_findings_malware ON public.component_analysis_malware_findings USING btree (malware_purl);


--
-- Name: idx_component_analysis_malware_queue_component; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_analysis_malware_queue_component ON public.component_analysis_malware_queue USING btree (component_purl, created_at DESC);


--
-- Name: idx_component_analysis_malware_queue_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_analysis_malware_queue_status ON public.component_analysis_malware_queue USING btree (status, created_at);


--
-- Name: idx_component_malware_findings_triage_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_malware_findings_triage_lookup ON public.component_malware_findings_triage USING btree (test_id, component_purl, malware_purl);


--
-- Name: idx_component_malware_findings_triage_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_malware_findings_triage_project ON public.component_malware_findings_triage USING btree (project_id, updated_at DESC);


--
-- Name: idx_component_malware_findings_triage_test; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_malware_findings_triage_test ON public.component_malware_findings_triage USING btree (test_id, updated_at DESC);


--
-- Name: idx_components_licenses; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_components_licenses ON public.components USING gin (licenses);


--
-- Name: idx_components_purl; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_components_purl ON public.components USING btree (purl);


--
-- Name: idx_components_purl_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_components_purl_trgm ON public.components USING gin (purl public.gin_trgm_ops);


--
-- Name: idx_components_revision; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_components_revision ON public.components USING btree (revision_id);


--
-- Name: idx_connector_configs_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connector_configs_scope ON public.connector_configs USING btree (scope_type, scope_id);


--
-- Name: idx_ingest_queue_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ingest_queue_status ON public.ingest_queue USING btree (status, created_at);


--
-- Name: idx_jira_delivery_attempts_mapping; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jira_delivery_attempts_mapping ON public.jira_delivery_attempts USING btree (jira_issue_mapping_id, created_at DESC) WHERE (jira_issue_mapping_id IS NOT NULL);


--
-- Name: idx_jira_delivery_attempts_project_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jira_delivery_attempts_project_created ON public.jira_delivery_attempts USING btree (project_id, created_at DESC);


--
-- Name: idx_jira_entity_settings_project_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jira_entity_settings_project_level ON public.jira_entity_settings USING btree (project_id, config_level, config_target_id);


--
-- Name: idx_jira_issue_mappings_component_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jira_issue_mappings_component_lookup ON public.jira_issue_mappings USING btree (project_id, test_id, component_purl, updated_at DESC) WHERE ((test_id IS NOT NULL) AND (component_purl IS NOT NULL));


--
-- Name: idx_jira_issue_mappings_group_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jira_issue_mappings_group_lookup ON public.jira_issue_mappings USING btree (project_id, alert_group_id, status, updated_at DESC);


--
-- Name: idx_jira_issue_mappings_owner_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jira_issue_mappings_owner_lookup ON public.jira_issue_mappings USING btree (project_id, config_level, config_target_id, status, updated_at DESC);


--
-- Name: idx_jira_metadata_cache_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jira_metadata_cache_lookup ON public.jira_metadata_cache USING btree (project_id, base_url_hash, metadata_type, metadata_scope_key);


--
-- Name: idx_product_group_grants_group_product; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_product_group_grants_group_product ON public.product_group_grants USING btree (group_id, product_id);


--
-- Name: idx_products_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_products_created_by ON public.products USING btree (created_by);


--
-- Name: idx_products_owner_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_products_owner_group_id ON public.products USING btree (owner_group_id);


--
-- Name: idx_products_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_products_project_id ON public.products USING btree (project_id);


--
-- Name: idx_project_memberships_project_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_project_memberships_project_user ON public.project_memberships USING btree (project_id, user_id);


--
-- Name: idx_project_memberships_user_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_project_memberships_user_project ON public.project_memberships USING btree (user_id, project_id);


--
-- Name: idx_project_memberships_user_project_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_project_memberships_user_project_role ON public.project_memberships USING btree (user_id, project_id, project_role);


--
-- Name: idx_projects_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_projects_created_by ON public.projects USING btree (created_by);


--
-- Name: idx_queue_poll; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_queue_poll ON public.source_malware_input_queue USING btree (status, created_at);


--
-- Name: idx_refresh_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_expires ON public.refresh_tokens USING btree (expires_at);


--
-- Name: idx_refresh_tokens_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_user ON public.refresh_tokens USING btree (user_id);


--
-- Name: idx_results_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_results_lookup ON public.source_malware_input_results USING btree (component_purl, verdict);


--
-- Name: idx_revisions_tags_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_revisions_tags_gin ON public.test_revisions USING gin (tags);


--
-- Name: idx_revisions_test_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_revisions_test_created ON public.test_revisions USING btree (test_id, created_at DESC);


--
-- Name: idx_scan_component_results_purl_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scan_component_results_purl_created ON public.source_malware_input_component_results USING btree (component_purl, created_at DESC);


--
-- Name: idx_scan_component_results_source_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scan_component_results_source_created ON public.source_malware_input_component_results USING btree (source_id, created_at DESC);


--
-- Name: idx_test_revision_change_summary_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_change_summary_project ON public.test_revision_change_summary USING btree (project_id, created_at DESC);


--
-- Name: idx_test_revision_change_summary_test; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_change_summary_test ON public.test_revision_change_summary USING btree (test_id, created_at DESC);


--
-- Name: idx_test_revision_finding_diff_queue_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_finding_diff_queue_status ON public.test_revision_finding_diff_queue USING btree (status, updated_at);


--
-- Name: idx_test_revision_finding_diff_queue_test; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_finding_diff_queue_test ON public.test_revision_finding_diff_queue USING btree (test_id, created_at DESC);


--
-- Name: idx_test_revision_finding_diffs_project_revision; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_finding_diffs_project_revision ON public.test_revision_finding_diffs USING btree (project_id, to_revision_id, created_at DESC);


--
-- Name: idx_test_revision_finding_diffs_test_revision_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_finding_diffs_test_revision_type ON public.test_revision_finding_diffs USING btree (test_id, to_revision_id, diff_type, created_at DESC);


--
-- Name: idx_test_revision_malware_summary_queue_revision; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_malware_summary_queue_revision ON public.test_revision_malware_summary_queue USING btree (revision_id, created_at DESC);


--
-- Name: idx_test_revision_malware_summary_queue_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_revision_malware_summary_queue_status ON public.test_revision_malware_summary_queue USING btree (status, created_at);


--
-- Name: idx_user_group_members_user_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_group_members_user_group ON public.user_group_members USING btree (user_id, group_id);


--
-- Name: idx_user_groups_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_groups_project_id ON public.user_groups USING btree (project_id);


--
-- Name: idx_user_settings_selected_project; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_settings_selected_project ON public.user_settings USING btree (selected_project_id);


--
-- Name: uq_component_analysis_malware_queue_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_component_analysis_malware_queue_active ON public.component_analysis_malware_queue USING btree (component_purl) WHERE (status = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text]));


--
-- Name: uq_connector_configs_global; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_connector_configs_global ON public.connector_configs USING btree (connector_type) WHERE ((scope_type = 'GLOBAL'::text) AND (scope_id IS NULL));


--
-- Name: uq_connector_configs_scoped; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_connector_configs_scoped ON public.connector_configs USING btree (connector_type, scope_type, scope_id) WHERE ((scope_type <> 'GLOBAL'::text) AND (scope_id IS NOT NULL));


--
-- Name: uq_products_project_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_products_project_name ON public.products USING btree (project_id, lower(name));


--
-- Name: uq_projects_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_projects_name ON public.projects USING btree (lower(name));


--
-- Name: uq_revisions_active_per_test; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_revisions_active_per_test ON public.test_revisions USING btree (test_id) WHERE (is_active = true);


--
-- Name: uq_scopes_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_scopes_name ON public.scopes USING btree (product_id, lower(name));


--
-- Name: uq_test_revision_finding_diffs_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_test_revision_finding_diffs_identity ON public.test_revision_finding_diffs USING btree (to_revision_id, finding_type, component_purl, malware_purl);


--
-- Name: uq_tests_name_type; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tests_name_type ON public.tests USING btree (scope_id, lower(name), sbom_standard, sbom_spec_version);


--
-- Name: uq_tests_public_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_tests_public_token ON public.tests USING btree (public_token) WHERE (public_token IS NOT NULL);


--
-- Name: uq_user_groups_project_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_user_groups_project_name ON public.user_groups USING btree (project_id, lower(name));


--
-- Name: ux_alert_dedup_rules_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_alert_dedup_rules_identity ON public.alert_dedup_rules USING btree (project_id, alert_type, dedup_scope, COALESCE(product_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(test_id, '00000000-0000-0000-0000-000000000000'::uuid));


--
-- Name: ux_jira_issue_mappings_owner_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_jira_issue_mappings_owner_identity ON public.jira_issue_mappings USING btree (project_id, config_level, config_target_id, alert_group_id, COALESCE(dedup_rule_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE ((test_id IS NULL) AND ((component_purl IS NULL) OR (btrim(component_purl) = ''::text)));


--
-- Name: ux_jira_issue_mappings_open_component; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_jira_issue_mappings_open_component ON public.jira_issue_mappings USING btree (project_id, test_id, component_purl) WHERE ((status = 'OPEN'::text) AND (test_id IS NOT NULL) AND (component_purl IS NOT NULL));


--
-- Name: product_group_grants trg_product_group_grants_validate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_product_group_grants_validate BEFORE INSERT OR UPDATE OF product_id, group_id ON public.product_group_grants FOR EACH ROW EXECUTE FUNCTION public.ctwall_product_group_grants_validate();


--
-- Name: products trg_products_validate_owner_group; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_products_validate_owner_group BEFORE INSERT OR UPDATE OF owner_group_id, project_id, created_by ON public.products FOR EACH ROW EXECUTE FUNCTION public.ctwall_products_validate_owner_group();


--
-- Name: alert_connector_settings alert_connector_settings_jira_dedup_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_connector_settings
    ADD CONSTRAINT alert_connector_settings_jira_dedup_rule_id_fkey FOREIGN KEY (jira_dedup_rule_id) REFERENCES public.alert_dedup_rules(id) ON DELETE SET NULL;


--
-- Name: alert_connector_settings alert_connector_settings_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_connector_settings
    ADD CONSTRAINT alert_connector_settings_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: alert_dedup_rules alert_dedup_rules_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dedup_rules
    ADD CONSTRAINT alert_dedup_rules_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE;


--
-- Name: alert_dedup_rules alert_dedup_rules_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dedup_rules
    ADD CONSTRAINT alert_dedup_rules_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: alert_dedup_rules alert_dedup_rules_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dedup_rules
    ADD CONSTRAINT alert_dedup_rules_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.scopes(id) ON DELETE CASCADE;


--
-- Name: alert_dedup_rules alert_dedup_rules_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dedup_rules
    ADD CONSTRAINT alert_dedup_rules_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: alert_detection_modes alert_detection_modes_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_detection_modes
    ADD CONSTRAINT alert_detection_modes_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: alert_dispatch_queue alert_dispatch_queue_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dispatch_queue
    ADD CONSTRAINT alert_dispatch_queue_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.alert_groups(id) ON DELETE CASCADE;


--
-- Name: alert_dispatch_queue alert_dispatch_queue_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_dispatch_queue
    ADD CONSTRAINT alert_dispatch_queue_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: alert_groups alert_groups_acknowledged_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_acknowledged_by_fkey FOREIGN KEY (acknowledged_by) REFERENCES public.users(id);


--
-- Name: alert_groups alert_groups_closed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_closed_by_fkey FOREIGN KEY (closed_by) REFERENCES public.users(id);


--
-- Name: alert_groups alert_groups_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: alert_occurrences alert_occurrences_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.alert_groups(id) ON DELETE CASCADE;


--
-- Name: alert_occurrences alert_occurrences_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE SET NULL;


--
-- Name: alert_occurrences alert_occurrences_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: alert_occurrences alert_occurrences_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.scopes(id) ON DELETE SET NULL;


--
-- Name: alert_occurrences alert_occurrences_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_occurrences
    ADD CONSTRAINT alert_occurrences_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE SET NULL;


--
-- Name: alert_routes alert_routes_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_routes
    ADD CONSTRAINT alert_routes_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: api_tokens api_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: audit_logs audit_logs_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: component_analysis_malware_findings component_analysis_malware_fi_source_malware_input_result__fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_analysis_malware_findings
    ADD CONSTRAINT component_analysis_malware_fi_source_malware_input_result__fkey FOREIGN KEY (source_malware_input_result_id) REFERENCES public.source_malware_input_results(id) ON DELETE CASCADE;


--
-- Name: component_malware_findings_triage component_malware_findings_triage_author_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_malware_findings_triage
    ADD CONSTRAINT component_malware_findings_triage_author_id_fkey FOREIGN KEY (author_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: component_malware_findings_triage component_malware_findings_triage_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_malware_findings_triage
    ADD CONSTRAINT component_malware_findings_triage_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: component_malware_findings_triage component_malware_findings_triage_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_malware_findings_triage
    ADD CONSTRAINT component_malware_findings_triage_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: component_overrides component_overrides_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_overrides
    ADD CONSTRAINT component_overrides_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: components components_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.components
    ADD CONSTRAINT components_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.test_revisions(id) ON DELETE CASCADE;


--
-- Name: products fk_products_project_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT fk_products_project_id FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: jira_delivery_attempts jira_delivery_attempts_alert_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_delivery_attempts
    ADD CONSTRAINT jira_delivery_attempts_alert_group_id_fkey FOREIGN KEY (alert_group_id) REFERENCES public.alert_groups(id) ON DELETE SET NULL;


--
-- Name: jira_delivery_attempts jira_delivery_attempts_dedup_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_delivery_attempts
    ADD CONSTRAINT jira_delivery_attempts_dedup_rule_id_fkey FOREIGN KEY (dedup_rule_id) REFERENCES public.alert_dedup_rules(id) ON DELETE SET NULL;


--
-- Name: jira_delivery_attempts jira_delivery_attempts_jira_issue_mapping_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_delivery_attempts
    ADD CONSTRAINT jira_delivery_attempts_jira_issue_mapping_id_fkey FOREIGN KEY (jira_issue_mapping_id) REFERENCES public.jira_issue_mappings(id) ON DELETE SET NULL;


--
-- Name: jira_delivery_attempts jira_delivery_attempts_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_delivery_attempts
    ADD CONSTRAINT jira_delivery_attempts_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: jira_delivery_attempts jira_delivery_attempts_queue_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_delivery_attempts
    ADD CONSTRAINT jira_delivery_attempts_queue_job_id_fkey FOREIGN KEY (queue_job_id) REFERENCES public.alert_dispatch_queue(id) ON DELETE SET NULL;


--
-- Name: jira_entity_settings jira_entity_settings_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_entity_settings
    ADD CONSTRAINT jira_entity_settings_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: jira_issue_mappings jira_issue_mappings_alert_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_issue_mappings
    ADD CONSTRAINT jira_issue_mappings_alert_group_id_fkey FOREIGN KEY (alert_group_id) REFERENCES public.alert_groups(id) ON DELETE CASCADE;


--
-- Name: jira_issue_mappings jira_issue_mappings_dedup_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_issue_mappings
    ADD CONSTRAINT jira_issue_mappings_dedup_rule_id_fkey FOREIGN KEY (dedup_rule_id) REFERENCES public.alert_dedup_rules(id) ON DELETE SET NULL;


--
-- Name: jira_issue_mappings jira_issue_mappings_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_issue_mappings
    ADD CONSTRAINT jira_issue_mappings_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: jira_issue_mappings jira_issue_mappings_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_issue_mappings
    ADD CONSTRAINT jira_issue_mappings_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: jira_metadata_cache jira_metadata_cache_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_metadata_cache
    ADD CONSTRAINT jira_metadata_cache_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: product_group_grants product_group_grants_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.product_group_grants
    ADD CONSTRAINT product_group_grants_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: product_group_grants product_group_grants_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.product_group_grants
    ADD CONSTRAINT product_group_grants_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.user_groups(id) ON DELETE CASCADE;


--
-- Name: product_group_grants product_group_grants_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.product_group_grants
    ADD CONSTRAINT product_group_grants_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE;


--
-- Name: products products_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: products products_owner_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_owner_group_id_fkey FOREIGN KEY (owner_group_id) REFERENCES public.user_groups(id) ON DELETE RESTRICT;


--
-- Name: project_memberships project_memberships_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_memberships
    ADD CONSTRAINT project_memberships_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: project_memberships project_memberships_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_memberships
    ADD CONSTRAINT project_memberships_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_memberships project_memberships_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_memberships
    ADD CONSTRAINT project_memberships_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: projects projects_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: refresh_tokens refresh_tokens_replaced_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_replaced_by_id_fkey FOREIGN KEY (replaced_by_id) REFERENCES public.refresh_tokens(id) ON DELETE SET NULL;


--
-- Name: refresh_tokens refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: scopes scopes_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE;


--
-- Name: source_malware_input_component_results source_malware_input_component_results_analysis_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_component_results
    ADD CONSTRAINT source_malware_input_component_results_analysis_result_id_fkey FOREIGN KEY (analysis_result_id) REFERENCES public.source_malware_input_results(id) ON DELETE CASCADE;


--
-- Name: source_malware_input_component_results source_malware_input_component_results_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_component_results
    ADD CONSTRAINT source_malware_input_component_results_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.source_malware_input_queue(id) ON DELETE CASCADE;


--
-- Name: source_malware_input_queue source_malware_input_queue_scanner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_malware_input_queue
    ADD CONSTRAINT source_malware_input_queue_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.source_scanners(id) ON DELETE CASCADE;


--
-- Name: source_scanners source_scanners_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_scanners
    ADD CONSTRAINT source_scanners_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.scan_malware_source(id) ON DELETE RESTRICT;


--
-- Name: test_revision_change_summary test_revision_change_summary_from_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_change_summary
    ADD CONSTRAINT test_revision_change_summary_from_revision_id_fkey FOREIGN KEY (from_revision_id) REFERENCES public.test_revisions(id) ON DELETE SET NULL;


--
-- Name: test_revision_change_summary test_revision_change_summary_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_change_summary
    ADD CONSTRAINT test_revision_change_summary_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: test_revision_change_summary test_revision_change_summary_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_change_summary
    ADD CONSTRAINT test_revision_change_summary_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: test_revision_change_summary test_revision_change_summary_to_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_change_summary
    ADD CONSTRAINT test_revision_change_summary_to_revision_id_fkey FOREIGN KEY (to_revision_id) REFERENCES public.test_revisions(id) ON DELETE CASCADE;


--
-- Name: test_revision_finding_diff_queue test_revision_finding_diff_queue_from_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diff_queue
    ADD CONSTRAINT test_revision_finding_diff_queue_from_revision_id_fkey FOREIGN KEY (from_revision_id) REFERENCES public.test_revisions(id) ON DELETE SET NULL;


--
-- Name: test_revision_finding_diff_queue test_revision_finding_diff_queue_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diff_queue
    ADD CONSTRAINT test_revision_finding_diff_queue_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: test_revision_finding_diff_queue test_revision_finding_diff_queue_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diff_queue
    ADD CONSTRAINT test_revision_finding_diff_queue_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: test_revision_finding_diff_queue test_revision_finding_diff_queue_to_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diff_queue
    ADD CONSTRAINT test_revision_finding_diff_queue_to_revision_id_fkey FOREIGN KEY (to_revision_id) REFERENCES public.test_revisions(id) ON DELETE CASCADE;


--
-- Name: test_revision_finding_diffs test_revision_finding_diffs_from_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diffs
    ADD CONSTRAINT test_revision_finding_diffs_from_revision_id_fkey FOREIGN KEY (from_revision_id) REFERENCES public.test_revisions(id) ON DELETE SET NULL;


--
-- Name: test_revision_finding_diffs test_revision_finding_diffs_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diffs
    ADD CONSTRAINT test_revision_finding_diffs_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: test_revision_finding_diffs test_revision_finding_diffs_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diffs
    ADD CONSTRAINT test_revision_finding_diffs_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: test_revision_finding_diffs test_revision_finding_diffs_to_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_finding_diffs
    ADD CONSTRAINT test_revision_finding_diffs_to_revision_id_fkey FOREIGN KEY (to_revision_id) REFERENCES public.test_revisions(id) ON DELETE CASCADE;


--
-- Name: test_revision_malware_summary_queue test_revision_malware_summary_queue_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_malware_summary_queue
    ADD CONSTRAINT test_revision_malware_summary_queue_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.test_revisions(id) ON DELETE CASCADE;


--
-- Name: test_revision_malware_summary test_revision_malware_summary_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revision_malware_summary
    ADD CONSTRAINT test_revision_malware_summary_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.test_revisions(id) ON DELETE CASCADE;


--
-- Name: test_revisions test_revisions_sbom_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revisions
    ADD CONSTRAINT test_revisions_sbom_sha256_fkey FOREIGN KEY (sbom_sha256) REFERENCES public.sbom_objects(sha256);


--
-- Name: test_revisions test_revisions_test_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_revisions
    ADD CONSTRAINT test_revisions_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.tests(id) ON DELETE CASCADE;


--
-- Name: tests tests_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tests
    ADD CONSTRAINT tests_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.scopes(id) ON DELETE CASCADE;


--
-- Name: user_group_members user_group_members_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_members
    ADD CONSTRAINT user_group_members_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: user_group_members user_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_members
    ADD CONSTRAINT user_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.user_groups(id) ON DELETE CASCADE;


--
-- Name: user_group_members user_group_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_members
    ADD CONSTRAINT user_group_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_groups user_groups_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: user_groups user_groups_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: user_settings user_settings_selected_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_selected_project_id_fkey FOREIGN KEY (selected_project_id) REFERENCES public.projects(id) ON DELETE SET NULL;


--
-- Name: user_settings user_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
--



-- Seed singleton schedule row expected by runtime APIs.
INSERT INTO public.component_analysis_malware_schedule (id, enabled, interval_seconds, updated_at)
VALUES (1, TRUE, 21600, NOW())
ON CONFLICT (id) DO NOTHING;
