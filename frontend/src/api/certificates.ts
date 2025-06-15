import ApiClient from './ApiClient';
import type { Certificate } from '@/types/Certificate';
import type {CertificateRequirements} from "@/types/CertificateRequirements.ts";

export const fetchCertificates = async (): Promise<Certificate[]> => {
    return await ApiClient.get<Certificate[]>('/certificates');
};

export const fetchCertificatePassword = async (id: number): Promise<Certificate> => {
    return await ApiClient.get<Certificate>(`/certificates/${id}/password`);
};

export const downloadCertificate = async (id: number): Promise<{ filename: string; blob: Blob }> => {
    return await ApiClient.get_download(`/certificates/${id}/download`);
};

export const createCertificate = async (certReq: CertificateRequirements): Promise<number> => {
    const cert = await ApiClient.post<Certificate>('/certificates', certReq);
    return cert.id;
};

export const deleteCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/${id}`);
};
