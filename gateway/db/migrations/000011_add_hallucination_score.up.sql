-- Phase 14: Hallucination detection — score column on agent_runs.
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS hallucination_score FLOAT;
CREATE INDEX IF NOT EXISTS idx_agent_runs_hallucination
    ON agent_runs (hallucination_score)
    WHERE hallucination_score IS NOT NULL;
