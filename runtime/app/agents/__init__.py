from . import coding_agent, browser_agent, devops_agent, direct_agent

AGENT_REGISTRY = {
    "coding_agent": coding_agent,
    "browser_agent": browser_agent,
    "devops_agent": devops_agent,
    "direct_agent": direct_agent,
}

__all__ = ["AGENT_REGISTRY"]
