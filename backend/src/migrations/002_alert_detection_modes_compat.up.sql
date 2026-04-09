-- Compatibility migration for existing databases:
-- ensure alert_detection_modes schema exists after baseline cleanup.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.alert_detection_modes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    mode text NOT NULL,
    enabled boolean NOT NULL,
    severity text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'alert_detection_modes_pkey'
          AND conrelid = 'public.alert_detection_modes'::regclass
    ) THEN
        ALTER TABLE ONLY public.alert_detection_modes
            ADD CONSTRAINT alert_detection_modes_pkey PRIMARY KEY (id);
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_alert_detection_modes_project_mode'
          AND conrelid = 'public.alert_detection_modes'::regclass
    ) THEN
        ALTER TABLE ONLY public.alert_detection_modes
            ADD CONSTRAINT uq_alert_detection_modes_project_mode UNIQUE (project_id, mode);
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'alert_detection_modes_mode_check'
          AND conrelid = 'public.alert_detection_modes'::regclass
    ) THEN
        ALTER TABLE ONLY public.alert_detection_modes
            ADD CONSTRAINT alert_detection_modes_mode_check
            CHECK ((mode = ANY (ARRAY['PURL_VERSION_SMART'::text, 'PURL_CONTAINS_PREFIX'::text])));
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'alert_detection_modes_severity_check'
          AND conrelid = 'public.alert_detection_modes'::regclass
    ) THEN
        ALTER TABLE ONLY public.alert_detection_modes
            ADD CONSTRAINT alert_detection_modes_severity_check
            CHECK ((severity = ANY (ARRAY['INFO'::text, 'WARN'::text, 'ERROR'::text])));
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'alert_detection_modes_project_id_fkey'
          AND conrelid = 'public.alert_detection_modes'::regclass
    ) THEN
        ALTER TABLE ONLY public.alert_detection_modes
            ADD CONSTRAINT alert_detection_modes_project_id_fkey
            FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_alert_detection_modes_project_mode
    ON public.alert_detection_modes USING btree (project_id, mode);
