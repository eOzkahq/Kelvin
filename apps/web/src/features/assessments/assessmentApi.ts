import { apiClient } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { demoAssessmentProvider } from "./demoProvider";
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
  } catch (err: unknown) {
    throw new Error(`Failed to cancel assessment: ${(err as Error).message}`, { cause: err });
  }
}

export async function createAssessment(payload: CreateAssessmentPayload): Promise<{ id: string }> {
  if (isDemoMode()) {
    return demoAssessmentProvider.createAssessment(payload);
  }
  return apiClient.post<{ id: string }>("/assessments", payload, {
    headers: {
      "Idempotency-Key": payload.idempotencyKey,
    },
  });
}

export function resetMockAssessments(): void {
  demoAssessmentProvider.resetMockAssessments();
}
