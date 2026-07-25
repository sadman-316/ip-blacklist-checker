import { UserProfile } from "./types";

export interface CompanyCredential extends UserProfile {
  passwordHash: string; // Plaintext or simple representation for direct manual configuration in code
}

// ============================================================================
// COMPANY DIRECTORY & SECURE ACCESS CREDENTIALS
// ============================================================================
// You can manually add, edit, or change emails, passwords, names, and roles
// for your team members directly below.
// ============================================================================
export const COMPANY_CREDENTIALS: CompanyCredential[] = [
  {
    uid: "admin_pranto",
    email: "mzpranto71@gmail.com",
    displayName: "Admin Pranto",
    role: "admin",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "admin1234" // <- Change your Admin Password here!
  },
  {
    uid: "emp_redwan",
    email: "redwan@wolast.com",
    displayName: "Redwan (Wolast)",
    role: "admin",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "redwan1234"
  },
  {
    uid: "emp_sarah",
    email: "sarah@company.com",
    displayName: "Sarah Connor (Operations)",
    role: "user",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "sarah5678" // <- Employee Password
  },
  {
    uid: "emp_john",
    email: "john@company.com",
    displayName: "John Doe (Support)",
    role: "user",
    status: "active",
    createdAt: "2026-07-12T00:00:00.000Z",
    passwordHash: "john9012" // <- Employee Password
  }
];
