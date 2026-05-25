import type { Principal } from "@icp-sdk/core/principal";
export interface Some<T> {
    __kind__: "Some";
    value: T;
}
export interface None {
    __kind__: "None";
}
export type Option<T> = Some<T> | None;
export class ExternalBlob {
    getBytes(): Promise<Uint8Array<ArrayBuffer>>;
    getDirectURL(): string;
    static fromURL(url: string): ExternalBlob;
    static fromBytes(blob: Uint8Array<ArrayBuffer>): ExternalBlob;
    withUploadProgress(onProgress: (percentage: number) => void): ExternalBlob;
}
export interface AIActQuery {
    context?: string;
    question: string;
}
export interface TransformationOutput {
    status: bigint;
    body: Uint8Array;
    headers: Array<http_header>;
}
export interface RiskEvent {
    id: string;
    issueType: string;
    suggestedAction: string;
    description: string;
    timestamp: bigint;
    category: RiskCategory;
    severity: string;
    riskScore: bigint;
}
export interface CybersecurityQuery {
    context?: string;
    question: string;
}
export interface DocumentMetadata {
    id: string;
    regulation: Regulation;
    owner: Principal;
    blob: ExternalBlob;
    compliance?: ComplianceResult;
    hash: Uint8Array;
    filename: string;
    timestamp: bigint;
    companyName: string;
}
export interface RepositoryMetadata {
    id: string;
    url: string;
    owner: Principal;
    name: string;
    cybersecurity?: CybersecurityResult;
    timestamp: bigint;
}
export interface RiskAnalysis {
    recommendations: string;
    summary: string;
    events: Array<RiskEvent>;
    category: RiskCategory;
    currentScore: bigint;
}
export interface CybersecurityResult {
    status: string;
    recommendations: string;
    score: bigint;
    vulnerabilities: string;
}
export interface http_header {
    value: string;
    name: string;
}
export interface http_request_result {
    status: bigint;
    body: Uint8Array;
    headers: Array<http_header>;
}
export interface CybersecurityResponse {
    references?: string;
    answer: string;
    securityTips?: string;
}
export interface AIActResponse {
    complianceTips?: string;
    references?: string;
    answer: string;
}
export interface TransformationInput {
    context: Uint8Array;
    response: http_request_result;
}
export interface ComplianceResult {
    status: string;
    recommendations: string;
    score: bigint;
}
export interface UserProfile {
    name: string;
}
export enum Regulation {
    usAIRegulations = "usAIRegulations",
    euAIAct = "euAIAct"
}
export enum RiskCategory {
    low = "low",
    high = "high",
    medium = "medium"
}
export enum UserRole {
    admin = "admin",
    user = "user",
    guest = "guest"
}
export interface backendInterface {
    addRepository(name: string, url: string): Promise<string>;
    aiActAssistant(aiQuery: AIActQuery): Promise<AIActResponse>;
    analyzeRepository(repositoryId: string): Promise<CybersecurityResult>;
    assignCallerUserRole(user: Principal, role: UserRole): Promise<void>;
    cybersecurityAssistant(cyberQuery: CybersecurityQuery): Promise<CybersecurityResponse>;
    generateSDKSecret(): Promise<string>;
    getAllDocuments(): Promise<Array<DocumentMetadata>>;
    getAllRepositories(): Promise<Array<RepositoryMetadata>>;
    getCallerUserProfile(): Promise<UserProfile | null>;
    getCallerUserRole(): Promise<UserRole>;
    getComplianceDashboard(): Promise<Array<DocumentMetadata>>;
    getCybersecurityDashboard(): Promise<Array<RepositoryMetadata>>;
    getExampleDocument(): Promise<DocumentMetadata | null>;
    getExampleRepository(): Promise<RepositoryMetadata | null>;
    getRiskAnalysis(): Promise<RiskAnalysis>;
    getRiskEvents(): Promise<Array<RiskEvent>>;
    getSDKSecret(): Promise<string | null>;
    getUserProfile(user: Principal): Promise<UserProfile | null>;
    initializeAccessControl(): Promise<void>;
    isCallerAdmin(): Promise<boolean>;
    makeGetOutcall(url: string): Promise<string>;
    makePostOutcall(url: string, body: string): Promise<string>;
    runRiskAnalysis(): Promise<RiskAnalysis>;
    saveCallerUserProfile(profile: UserProfile): Promise<void>;
    transform(input: TransformationInput): Promise<TransformationOutput>;
    updateCompanyName(documentId: string, newCompanyName: string): Promise<void>;
    updateComplianceScore(documentId: string, newScore: bigint): Promise<void>;
    updateCybersecurityScore(repositoryId: string, newScore: bigint): Promise<void>;
    uploadDocument(filename: string, hash: Uint8Array, regulation: Regulation, blob: ExternalBlob, companyName: string): Promise<string>;
    verifyDocument(hash: Uint8Array): Promise<DocumentMetadata | null>;
}
