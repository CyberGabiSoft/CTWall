-- Adds optional per-project lookback window (in days) for PURL_CONTAINS_PREFIX mode.
-- NULL means "all history".

ALTER TABLE IF EXISTS public.alert_detection_modes
    ADD COLUMN IF NOT EXISTS lookback_days integer;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'alert_detection_modes_lookback_days_check'
          AND conrelid = 'public.alert_detection_modes'::regclass
    ) THEN
        ALTER TABLE ONLY public.alert_detection_modes
            ADD CONSTRAINT alert_detection_modes_lookback_days_check
            CHECK ((lookback_days IS NULL) OR (lookback_days > 0));
    END IF;
END $$;
