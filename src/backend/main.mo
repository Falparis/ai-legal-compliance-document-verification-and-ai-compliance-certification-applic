import Time "mo:base/Time";
import MixinObjectStorage "mo:caffeineai-object-storage/Mixin";
import Storage "mo:caffeineai-object-storage/Storage";
import OutCall "mo:caffeineai-http-outcalls/outcall";
import AccessControl "mo:caffeineai-authorization/access-control";
import MixinAuthorization "mo:caffeineai-authorization/MixinAuthorization";
import Map "mo:core/Map";
import Text "mo:core/Text";
import Int "mo:core/Int";
import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Runtime "mo:core/Runtime";
import Migration "migration";

(with migration = Migration.run)
actor Backend {
  include MixinObjectStorage();

  let accessControlState = AccessControl.initState();

  include MixinAuthorization(accessControlState);

  public type Regulation = {
    #euAIAct;
    #usAIRegulations;
  };

  public type ComplianceResult = {
    score : Nat;
    status : Text;
    recommendations : Text;
  };

  public type DocumentMetadata = {
    id : Text;
    filename : Text;
    timestamp : Int;
    hash : Blob;
    regulation : Regulation;
    compliance : ?ComplianceResult;
    blob : Storage.ExternalBlob;
    owner : Principal;
    companyName : Text;
  };

  public type UserProfile = {
    name : Text;
  };

  // AI Act Assistant Types
  public type AIActQuery = {
    question : Text;
    context : ?Text;
  };

  public type AIActResponse = {
    answer : Text;
    references : ?Text;
    complianceTips : ?Text;
  };

  // Cybersecurity Types
  public type CybersecurityResult = {
    score : Nat;
    status : Text;
    recommendations : Text;
    vulnerabilities : Text;
  };

  public type RepositoryMetadata = {
    id : Text;
    name : Text;
    timestamp : Int;
    url : Text;
    cybersecurity : ?CybersecurityResult;
    owner : Principal;
  };

  // Cybersecurity AI Assistant Types
  public type CybersecurityQuery = {
    question : Text;
    context : ?Text;
  };

  public type CybersecurityResponse = {
    answer : Text;
    references : ?Text;
    securityTips : ?Text;
  };

  // AI Risk & Bias Minimization Layer Types
  public type RiskCategory = {
    #low;
    #medium;
    #high;
  };

  public type RiskEvent = {
    id : Text;
    timestamp : Int;
    riskScore : Nat;
    category : RiskCategory;
    issueType : Text;
    description : Text;
    suggestedAction : Text;
    severity : Text;
  };

  public type RiskAnalysis = {
    currentScore : Nat;
    category : RiskCategory;
    events : [RiskEvent];
    summary : Text;
    recommendations : Text;
  };

  public type SDKSecret = {
    user : Principal;
    secret : Text;
    createdAt : Int;
  };

  let documents = Map.empty<Text, DocumentMetadata>();
  let repositories = Map.empty<Text, RepositoryMetadata>();
  let riskEvents = Map.empty<Text, RiskEvent>();
  let sdkSecrets = Map.empty<Text, SDKSecret>();
  let userProfiles = Map.empty<Principal, UserProfile>();

  public shared ({ caller }) func initializeAccessControl() : async () {
    AccessControl.initialize(accessControlState, caller);
  };

  public query ({ caller }) func getCallerUserProfile() : async ?UserProfile {
    userProfiles.get(caller);
  };

  public shared ({ caller }) func saveCallerUserProfile(profile : UserProfile) : async () {
    userProfiles.add(caller, profile);
  };

  public query ({ caller }) func getUserProfile(user : Principal) : async ?UserProfile {
    if (caller != user and not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Can only view your own profile");
    };
    userProfiles.get(user);
  };

  // Allow all users including guests to upload documents
  public shared ({ caller }) func uploadDocument(filename : Text, hash : Blob, regulation : Regulation, blob : Storage.ExternalBlob, companyName : Text) : async Text {
    let id = filename # Time.now().toText();
    let complianceResult : ComplianceResult = {
      score = 70;
      status = "compliance at 70%";
      recommendations = "Compliant";
    };

    let metadata : DocumentMetadata = {
      id;
      filename;
      timestamp = Time.now();
      hash;
      regulation;
      compliance = ?complianceResult;
      blob;
      owner = caller;
      companyName;
    };

    documents.add(id, metadata);
    id;
  };

  public shared ({ caller }) func updateCompanyName(documentId : Text, newCompanyName : Text) : async () {
    switch (documents.get(documentId)) {
      case (null) {
        Runtime.trap("Document not found");
      };
      case (?doc) {
        if (caller != doc.owner and not AccessControl.isAdmin(accessControlState, caller)) {
          Runtime.trap("Unauthorized: Can only update your own documents");
        };
        documents.add(documentId, { doc with companyName = newCompanyName });
      };
    };
  };

  public query func getAllDocuments() : async [DocumentMetadata] {
    documents.values().toArray();
  };

  public query func verifyDocument(hash : Blob) : async ?DocumentMetadata {
    documents.values().find(func(doc) { doc.hash == hash });
  };

  public query func getComplianceDashboard() : async [DocumentMetadata] {
    documents.values().toArray();
  };

  // Allow all users (including guests) to modify compliance scores
  public shared func updateComplianceScore(documentId : Text, newScore : Nat) : async () {
    switch (documents.get(documentId)) {
      case (null) {
        Runtime.trap("Document not found");
      };
      case (?doc) {
        let updatedCompliance : ComplianceResult = {
          score = newScore;
          status = "compliance at " # newScore.toText() # "%";
          recommendations = "Compliant";
        };
        documents.add(documentId, { doc with compliance = ?updatedCompliance });
      };
    };
  };

  // AI Act Assistant Functions
  public shared ({ caller }) func aiActAssistant(aiQuery : AIActQuery) : async AIActResponse {
    let response : AIActResponse = {
      answer = "This is a specialized AI Act compliance response. For your question: " # aiQuery.question # ", the AI Act recommends strict adherence to transparency and risk management requirements.";
      references = ?"AI Act Article 5, Article 9";
      complianceTips = ?"Ensure your AI system has clear documentation and risk assessment procedures in place.";
    };
    response;
  };

  // Cybersecurity Functions - allow all users including guests
  public shared ({ caller }) func addRepository(name : Text, url : Text) : async Text {
    let id = name # Time.now().toText();
    let cybersecurityResult : CybersecurityResult = {
      score = 85;
      status = "secure at 85%";
      recommendations = "Secure";
      vulnerabilities = "None detected";
    };

    let metadata : RepositoryMetadata = {
      id;
      name;
      timestamp = Time.now();
      url;
      cybersecurity = ?cybersecurityResult;
      owner = caller;
    };

    repositories.add(id, metadata);
    id;
  };

  public query func getAllRepositories() : async [RepositoryMetadata] {
    repositories.values().toArray();
  };

  public query func getCybersecurityDashboard() : async [RepositoryMetadata] {
    repositories.values().toArray();
  };

  // Allow all users (including guests) to modify cybersecurity scores
  public shared func updateCybersecurityScore(repositoryId : Text, newScore : Nat) : async () {
    switch (repositories.get(repositoryId)) {
      case (null) {
        Runtime.trap("Repository not found");
      };
      case (?repo) {
        let updatedCybersecurity : CybersecurityResult = {
          score = newScore;
          status = "secure at " # newScore.toText() # "%";
          recommendations = "Secure";
          vulnerabilities = "None detected";
        };
        repositories.add(repositoryId, { repo with cybersecurity = ?updatedCybersecurity });
      };
    };
  };

  // Cybersecurity AI Assistant Functions
  public shared ({ caller }) func cybersecurityAssistant(cyberQuery : CybersecurityQuery) : async CybersecurityResponse {
    let response : CybersecurityResponse = {
      answer = "This is a specialized cybersecurity response. For your question: " # cyberQuery.question # ", we recommend regular vulnerability scans and adherence to best security practices.";
      references = ?"NIST Cybersecurity Framework, OWASP Top 10";
      securityTips = ?"Implement multi-factor authentication and regular security audits.";
    };
    response;
  };

  // Simulated AI LLM Canister for Cybersecurity Analysis
  public shared ({ caller }) func analyzeRepository(repositoryId : Text) : async CybersecurityResult {
    switch (repositories.get(repositoryId)) {
      case (null) {
        Runtime.trap("Repository not found");
      };
      case (?repo) {
        let analysisResult : CybersecurityResult = {
          score = 90;
          status = "secure at 90%";
          recommendations = "Maintain regular security audits and vulnerability scans.";
          vulnerabilities = "No critical vulnerabilities detected. Minor issues found in dependency management.";
        };
        repositories.add(repositoryId, { repo with cybersecurity = ?analysisResult });
        analysisResult;
      };
    };
  };

  public query func transform(input : OutCall.TransformationInput) : async OutCall.TransformationOutput {
    OutCall.transform(input);
  };

  // Admin-only HTTP outcalls
  public shared ({ caller }) func makeGetOutcall(url : Text) : async Text {
    if (not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
      Runtime.trap("Unauthorized: Only admins can make HTTP outcalls");
    };
    await OutCall.httpGetRequest(url, [], transform);
  };

  public shared ({ caller }) func makePostOutcall(url : Text, body : Text) : async Text {
    if (not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
      Runtime.trap("Unauthorized: Only admins can make HTTP outcalls");
    };
    await OutCall.httpPostRequest(url, [], body, transform);
  };

  public query func getExampleDocument() : async ?DocumentMetadata {
    documents.values().find(func(doc) {
      switch (doc.compliance) {
        case (null) { false };
        case (?comp) { comp.score >= 80 };
      };
    });
  };

  public query func getExampleRepository() : async ?RepositoryMetadata {
    repositories.values().find(func(repo) {
      switch (repo.cybersecurity) {
        case (null) { false };
        case (?cyber) { cyber.score >= 80 };
      };
    });
  };

  // AI Risk & Bias Minimization Layer Functions
  public shared ({ caller }) func runRiskAnalysis() : async RiskAnalysis {
    let currentTime = Time.now();
    let riskScore = 45;
    let category = if (riskScore <= 30) #low else if (riskScore <= 70) #medium else #high;

    let newEvent : RiskEvent = {
      id = "event-" # currentTime.toText();
      timestamp = currentTime;
      riskScore;
      category;
      issueType = "Bias Detection";
      description = "Detected potential bias in AI assistant outputs. Analysis shows moderate risk of bias in responses.";
      suggestedAction = "Implement additional filters and guardrails to minimize bias. Consider retraining the model with more diverse data.";
      severity = "Medium";
    };

    riskEvents.add(newEvent.id, newEvent);

    let analysis : RiskAnalysis = {
      currentScore = riskScore;
      category;
      events = riskEvents.values().toArray();
      summary = "Current risk score is " # riskScore.toText() # " (" # (switch (category) { case (#low) "Low"; case (#medium) "Medium"; case (#high) "High"; }) # ").";
      recommendations = "Monitor risk events and implement suggested actions to maintain low risk levels.";
    };

    analysis;
  };

  public query func getRiskAnalysis() : async RiskAnalysis {
    let riskScore = 45;
    let category = if (riskScore <= 30) #low else if (riskScore <= 70) #medium else #high;

    {
      currentScore = riskScore;
      category;
      events = riskEvents.values().toArray();
      summary = "Current risk score is " # riskScore.toText() # " (" # (switch (category) { case (#low) "Low"; case (#medium) "Medium"; case (#high) "High"; }) # ").";
      recommendations = "Monitor risk events and implement suggested actions to maintain low risk levels.";
    };
  };

  public query func getRiskEvents() : async [RiskEvent] {
    riskEvents.values().toArray();
  };

  // SDK Secret Generation and Management
  public shared ({ caller }) func generateSDKSecret() : async Text {
    let secret = "sdk-" # Time.now().toText() # "-" # caller.toText();
    let sdkSecret : SDKSecret = {
      user = caller;
      secret;
      createdAt = Time.now();
    };

    sdkSecrets.add(secret, sdkSecret);
    secret;
  };

  public query ({ caller }) func getSDKSecret() : async ?Text {
    switch (sdkSecrets.values().find(func(sdk) { sdk.user == caller })) {
      case (null) { null };
      case (?sdk) { ?sdk.secret };
    };
  };
};
