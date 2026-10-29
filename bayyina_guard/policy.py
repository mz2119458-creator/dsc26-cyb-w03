from dataclasses import dataclass, field

@dataclass(frozen=True)
class User:
    id: str
    role: str                       # partner | associate | paralegal | client | auditor
    client_id: str | None = None    # for client users: which Bayyina client they belong to
    matters: frozenset[str] = field(default_factory=frozenset)
    mfa: bool = False               # this session passed MFA

@dataclass(frozen=True)
class Document:
    id: str
    client_id: str
    matter_id: str
    confidentiality: str = "normal" # "normal" or "restricted"
    legal_hold: bool = False

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

VALID_ACTIONS = {"read", "comment", "upload_version", "delete", "share_external"}
VALID_ROLES = {"partner", "associate", "paralegal", "client", "auditor"}

ROLE_PERMISSIONS = {
    "partner": {"read", "comment", "upload_version", "delete", "share_external"},
    "associate": {"read", "comment", "upload_version"},
    "paralegal": {"read", "upload_version"},
    "client": {"read", "comment"},
    "auditor": set()
}

def authorize(user: User | None, action: str, doc: Document) -> Decision:
    if user is None or not user.id:
        return Decision(False, "unauthenticated")
     
    if action not in VALID_ACTIONS:
        return Decision(False, "unknown_action")
        
    if user.role not in VALID_ROLES:
        return Decision(False, "unknown_role")
        
    if action == "delete" and doc.legal_hold:
        return Decision(False, "legal_hold")
        
    # 1. Tenant check (Strict precedence before roles)
    if user.role == "client":
        if user.client_id is None or user.client_id != doc.client_id:
            return Decision(False, "tenant_mismatch")
            
    # 2. Assignment check for internal staff
    if user.role in ("associate", "paralegal"):
        if doc.matter_id not in user.matters:
            return Decision(False, "not_assigned")
            
    # 3. Role permissions check
    allowed_actions = ROLE_PERMISSIONS.get(user.role, set())
    if action not in allowed_actions:
        return Decision(False, "role_not_permitted")
        
    # 4. Confidentiality & Restricted check
    if user.role in ("client", "paralegal"):
        if doc.confidentiality != "normal":
            return Decision(False, "restricted")
            
    # 5. MFA requirement check (highest security barrier at the end)
    if doc.confidentiality != "normal" or action == "share_external":
        if not user.mfa:
            return Decision(False, "mfa_required")
            
    return Decision(True, "ok")

def visible_documents(user: User | None, docs: list[Document]) -> list[Document]:
    return [d for d in docs if authorize(user, "read", d).allowed]
