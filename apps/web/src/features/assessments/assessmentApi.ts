import { apiClient, ApiError } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { demoAssessmentProvider, mockProfiles, mockTargets } from "./demoProvider";
import type {
  AssessmentDetail,
  AssessmentRecord,
  AssessmentCancelResponse,
  CreateAssessmentPayload,
  ScanProfile,
  TargetOption,
} from "./types";

export type {
  AssessmentDetail,
  AssessmentRecord,
  AssessmentCancelResponse,
  CreateAssessmentPayload,
  ScanProfile,
  TargetOption,
};

export { mockProfiles, mockTargets };

export async function fetchProfiles(): Promise<ScanProfile[]> {
  if (isDemoMode()) {
    return demoAssessmentProvider.fetchProfiles();
  }
  return apiClient.get<ScanProfile[]>("/assessments/profiles");
}

export async function fetchTargets(): Promise<TargetOption[]> {
  if (isDemoMode()) {
    return demoAssessmentProvider.fetchTargets();
  }
  return apiClient.get<TargetOption[]>("/targets");
}

export async function fetchAssessments(): Promise<AssessmentRecord[]> {
  if (isDemoMode()) {
    return demoAssessmentProvider.fetchAssessments();
  }
  return apiClient.get<AssessmentRecord[]>("/assessments");
}

export async function fetchAssessmentDetail(id: string): Promise<AssessmentDetail> {
  if (isDemoMode()) {
    return demoAssessmentProvider.fetchAssessmentDetail(id);
  }
  return apiClient.get<AssessmentDetail>(`/assessments/${encodeURIComponent(id)}`);
}

export async function cancelAssessment(id: string): Promise<AssessmentCancelResponse> {
  if (isDemoMode()) {
    return demoAssessmentProvider.cancelAssessment(id);
  }
  try {
    return await apiClient.post<AssessmentCancelResponse>(`/assessments/${encodeURIComponent(id)}/cancel`, {});
  } catch (err) {
    if (err instanceof ApiError) {
      throw new Error(`Failed to cancel assessment: ${err.message}`);
    }
    throw err;
  }
}

export async function createAssessment(payload: CreateAssessmentPayload): Promise<{ id: string }> {
  if (isDemoMode()) {
    return demoAssessmentProvider.createAssessment(payload);
  }
  return apiClient.post<{ id: string }>("/assessments", payload, {
    headers: {
      "X-Idempotency-Key": payload.idempotencyKey,
    },
  });
}
