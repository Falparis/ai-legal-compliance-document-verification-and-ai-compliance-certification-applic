import Map "mo:core/Map";
import Principal "mo:core/Principal";
import Text "mo:core/Text";
import Order "mo:core/Order";

module {
  // ===== Old Red-Black Tree Map types (from older mo:core version) =====
  // These match the persistent format stored in the .most file
  type OldTree<K, V> = {
    #black : (OldTree<K, V>, K, V, OldTree<K, V>);
    #red : (OldTree<K, V>, K, V, OldTree<K, V>);
    #leaf;
  };

  type OldMap<K, V> = {
    root : OldTree<K, V>;
    size : Nat;
  };

  // ===== Old AccessControlState (has var userRoles) =====
  type UserRole = {
    #admin;
    #user;
    #guest;
  };

  public type OldAccessControlState = {
    var adminAssigned : Bool;
    var userRoles : OldMap<Principal, UserRole>;
  };

  public type NewAccessControlState = {
    var adminAssigned : Bool;
    userRoles : Map.Map<Principal, UserRole>;
  };

  // ===== Convert old red-black tree to new B-tree Map =====
  func migrateOldMap<K, V>(old : OldMap<K, V>, compare : (K, K) -> Order.Order) : Map.Map<K, V> {
    let newMap = Map.empty<K, V>();
    func traverse(tree : OldTree<K, V>) {
      switch tree {
        case (#leaf) {};
        case (#red(left, k, v, right)) {
          traverse(left);
          newMap.add(k, v);
          traverse(right);
        };
        case (#black(left, k, v, right)) {
          traverse(left);
          newMap.add(k, v);
          traverse(right);
        };
      };
    };
    traverse(old.root);
    newMap;
  };

  // Migrate accessControlState — convert var userRoles OldMap to non-var Map
  public func migrateAccessControlState(old : OldAccessControlState) : NewAccessControlState {
    {
      var adminAssigned = old.adminAssigned;
      userRoles = migrateOldMap<Principal, UserRole>(old.userRoles, Principal.compare);
    };
  };

  // ===== Document types =====
  type Regulation = {
    #euAIAct;
    #usAIRegulations;
  };

  type ComplianceResult = {
    score : Nat;
    status : Text;
    recommendations : Text;
  };

  type DocumentMetadata = {
    id : Text;
    filename : Text;
    timestamp : Int;
    hash : Blob;
    regulation : Regulation;
    compliance : ?ComplianceResult;
    blob : Blob;
    owner : Principal;
    companyName : Text;
  };

  type CybersecurityResult = {
    score : Nat;
    status : Text;
    recommendations : Text;
    vulnerabilities : Text;
  };

  type RepositoryMetadata = {
    id : Text;
    name : Text;
    timestamp : Int;
    url : Text;
    cybersecurity : ?CybersecurityResult;
    owner : Principal;
  };

  type RiskCategory = {
    #low;
    #medium;
    #high;
  };

  type RiskEvent = {
    id : Text;
    timestamp : Int;
    riskScore : Nat;
    category : RiskCategory;
    issueType : Text;
    description : Text;
    suggestedAction : Text;
    severity : Text;
  };

  type SDKSecret = {
    user : Principal;
    secret : Text;
    createdAt : Int;
  };

  type UserProfile = {
    name : Text;
  };

  // ===== Storage state (old format has extra blobTodeletete field) =====
  type OldStorageState = {
    var authorizedPrincipals : [Principal];
    var blobTodeletete : [Blob];
  };

  // ===== Old actor shape (matches .most file) =====
  type OldActor = {
    var accessControlState : OldAccessControlState;
    var documents : OldMap<Text, DocumentMetadata>;
    var repositories : OldMap<Text, RepositoryMetadata>;
    var riskEvents : OldMap<Text, RiskEvent>;
    var sdkSecrets : OldMap<Text, SDKSecret>;
    storage : OldStorageState;
    var userProfiles : OldMap<Principal, UserProfile>;
  };

  // ===== New actor shape =====
  type NewActor = {
    accessControlState : NewAccessControlState;
    documents : Map.Map<Text, DocumentMetadata>;
    repositories : Map.Map<Text, RepositoryMetadata>;
    riskEvents : Map.Map<Text, RiskEvent>;
    sdkSecrets : Map.Map<Text, SDKSecret>;
    userProfiles : Map.Map<Principal, UserProfile>;
  };

  public func run(old : OldActor) : NewActor {
    {
      accessControlState = migrateAccessControlState(old.accessControlState);
      documents = migrateOldMap<Text, DocumentMetadata>(old.documents, Text.compare);
      repositories = migrateOldMap<Text, RepositoryMetadata>(old.repositories, Text.compare);
      riskEvents = migrateOldMap<Text, RiskEvent>(old.riskEvents, Text.compare);
      sdkSecrets = migrateOldMap<Text, SDKSecret>(old.sdkSecrets, Text.compare);
      userProfiles = migrateOldMap<Principal, UserProfile>(old.userProfiles, Principal.compare);
    };
  };
};
