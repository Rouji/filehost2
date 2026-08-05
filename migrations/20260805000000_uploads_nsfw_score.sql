-- NULL means the upload hasn't been scanned yet (scanning disabled, or
-- `rensfw` hasn't reached it); otherwise holds the model's raw "unsafe"
-- probability (1 - P(SFW), so 0.0 is confidently clean, 1.0 is confidently
-- NSFW/NSFL). A real (possibly low) score is always written once a scan
-- completes, so NULL vs. non-NULL distinguishes "never scanned" from "clean".
ALTER TABLE uploads ADD COLUMN nsfw_score FLOAT NULL;
