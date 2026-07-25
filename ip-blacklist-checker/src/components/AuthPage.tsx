import React, { useState } from "react";
import { db } from "../firebase";
import { doc, setDoc, collection, query, where, getDocs } from "firebase/firestore";
import { ShieldAlert, ShieldCheck, Mail, Lock, ArrowRight, Loader2 } from "lucide-react";
import { motion } from "motion/react";
import { UserProfile } from "../types";
import { COMPANY_CREDENTIALS } from "../company-credentials";

interface AuthPageProps {
  onAuthSuccess: (user: UserProfile) => void;
}

export const AuthPage: React.FC<AuthPageProps> = ({ onAuthSuccess }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const trimmedEmail = email.trim().toLowerCase();

    try {
      let matchingCredential: any = null;

      // 1. Try central Express server authentication API first
      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: trimmedEmail, password })
        });

        const data = await res.json();

        if (res.ok && data.success && data.user) {
          matchingCredential = data.user;
        } else if (data && data.error) {
          // Explicit error returned by central authentication server
          throw new Error(data.error);
        }
      } catch (apiErr: any) {
        // If it's an explicit error from server (e.g. wrong password or unregistered), rethrow it
        if (apiErr.message && (
          apiErr.message.includes("Access Denied") ||
          apiErr.message.includes("Invalid email") ||
          apiErr.message.includes("suspended")
        )) {
          throw apiErr;
        }
        console.warn("Server auth endpoint unavailable, falling back to local credentials check:", apiErr);
      }

      // 2. Fallback to hardcoded credentials if server API was offline
      if (!matchingCredential) {
        matchingCredential = COMPANY_CREDENTIALS.find(
          (cred) => cred.email.toLowerCase() === trimmedEmail
        );
      }

      // 3. Fallback to local storage users
      if (!matchingCredential) {
        try {
          const localUsersStr = localStorage.getItem("wolast_local_users");
          if (localUsersStr) {
            const localUsers: UserProfile[] = JSON.parse(localUsersStr);
            const localFound = localUsers.find((u) => u.email.toLowerCase() === trimmedEmail);
            if (localFound) {
              matchingCredential = localFound;
            }
          }
        } catch (e) {}
      }

      // 4. Fallback to Firestore users lookup
      if (!matchingCredential) {
        try {
          const usersRef = collection(db, "users");
          const q = query(usersRef, where("email", "==", trimmedEmail));
          const querySnapshot = await Promise.race([
            getDocs(q),
            new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Timeout")), 2000))
          ]);

          if (!querySnapshot.empty) {
            matchingCredential = querySnapshot.docs[0].data() as UserProfile;
          }
        } catch (fErr) {
          console.warn("Firestore auth query timed out or failed:", fErr);
        }
      }

      if (!matchingCredential) {
        throw new Error(
          "Access Denied: This email address is not registered in the company employee directory."
        );
      }

      // Check password if fallback match was used
      if (matchingCredential.passwordHash && matchingCredential.passwordHash !== password) {
        throw new Error("Invalid email or password. Please verify your credentials.");
      }

      if (matchingCredential.status === "suspended") {
        throw new Error("Your account has been suspended. Please contact the administrator.");
      }

      // Extract UserProfile for the app state
      const profile: UserProfile = {
        uid: matchingCredential.uid,
        email: matchingCredential.email,
        displayName: matchingCredential.displayName,
        role: matchingCredential.role,
        createdAt: matchingCredential.createdAt,
        status: matchingCredential.status,
        passwordHash: matchingCredential.passwordHash,
      };

      // Save to localStorage for quick persistence on reload
      localStorage.setItem("wolast_shield_user", JSON.stringify(profile));

      // Pass user to parent component immediately
      onAuthSuccess(profile);
    } catch (err: any) {
      console.error("Auth error:", err);
      setError(err.message || "Authentication failed");
    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="min-h-screen bg-black flex flex-col justify-center relative overflow-hidden px-4 py-12 sm:px-6 lg:px-8 font-sans">
      {/* Premium Background Ambient Accents */}
      <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_top_right,rgba(220,38,38,0.08),transparent_45%)] pointer-events-none" />
      <div className="absolute bottom-0 right-0 w-full h-full bg-[radial-gradient(circle_at_bottom_left,rgba(220,38,38,0.05),transparent_50%)] pointer-events-none" />
      
      <div className="sm:mx-auto sm:w-full sm:max-w-md relative z-10">
        <div className="flex flex-col items-center">
          {/* Elegant Wolast Corporate Brand Shield */}
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-red-650 via-red-600 to-black flex items-center justify-center text-white shadow-[0_0_25px_rgba(220,38,38,0.3)] border border-red-500/20">
            <ShieldCheck className="w-9 h-9 text-red-500 animate-pulse" />
          </div>
          
          <div className="mt-6 text-center">
            <span className="text-[10px] font-black uppercase tracking-[0.25em] text-red-500 bg-red-500/10 px-3 py-1 rounded-full border border-red-500/20">
              Wolast Technologies
            </span>
            <h2 className="mt-3 text-2xl sm:text-3xl font-black text-white tracking-tight uppercase">
              WolastShield<span className="text-red-600 font-light">Pro</span>
            </h2>
            <p className="mt-2 text-xs text-zinc-400 font-semibold uppercase tracking-wider">
              IP Reputation Guard & Enterprise Network Threat Intelligence
            </p>
          </div>
        </div>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-2 sm:px-0 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="bg-zinc-950/90 backdrop-blur-md py-8 px-6 sm:px-10 shadow-[0_20px_50px_rgba(0,0,0,0.8)] border border-zinc-900 rounded-3xl space-y-6"
        >
          <div className="text-center border-b border-zinc-900 pb-4 space-y-1">
            <h3 className="text-xs font-black text-red-500 uppercase tracking-widest">
              Staff Authentication Portal
            </h3>
            <p className="text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">
              Protected by Wolast Secure Access Guidelines
            </p>
          </div>

          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="bg-red-500/10 border border-red-500/20 p-4 rounded-xl flex items-start gap-3"
            >
              <ShieldAlert className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
              <div className="space-y-1 text-xs text-red-200">
                <span className="font-bold block text-red-400">Access Restricted</span>
                <span className="font-medium leading-normal block">{error}</span>
                {error.includes("auth/operation-not-allowed") && (
                  <span className="block text-[10px] text-rose-300/85 mt-2 leading-normal font-medium bg-red-950/40 p-2 rounded-lg border border-red-900/30">
                    <strong>Admin Warning:</strong> Enable <strong>Email/Password</strong> credentials in your Firestore console backend setup.
                  </span>
                )}
              </div>
            </motion.div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-1.5">
              <label className="text-[10px] font-black text-zinc-400 uppercase tracking-widest block">
                Work Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-3.5 w-4.5 h-4.5 text-zinc-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@wolast.com"
                  className="w-full bg-zinc-900/80 border border-zinc-800 rounded-xl pl-11 pr-4 py-3 text-xs focus:bg-zinc-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20 focus:border-red-500/80 text-white font-semibold transition-all placeholder:text-zinc-650"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-black text-zinc-400 uppercase tracking-widest block">
                Secure Access Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-3.5 w-4.5 h-4.5 text-zinc-500" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-zinc-900/80 border border-zinc-800 rounded-xl pl-11 pr-4 py-3 text-xs focus:bg-zinc-900 focus:outline-hidden focus:ring-2 focus:ring-red-500/20 focus:border-red-500/80 text-white font-semibold transition-all placeholder:text-zinc-650"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-red-650 to-red-800 hover:from-red-600 hover:to-red-750 text-white font-black text-xs uppercase tracking-widest py-3.5 rounded-xl shadow-[0_4px_15px_rgba(220,38,38,0.25)] flex items-center justify-center gap-2 cursor-pointer transition-all mt-6 disabled:opacity-50 border border-white/5 active:scale-[0.98]"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Authenticating Server Token...
                </>
              ) : (
                <>
                  Authorize Node Connection
                  <ArrowRight className="w-4 h-4 text-red-500" />
                </>
              )}
            </button>
          </form>

          <div className="pt-3 border-t border-zinc-900 text-center text-[10px] text-zinc-500 font-bold uppercase tracking-wider">
            Enterprise Intranet Only • Unauthorized Access Monitored
          </div>
        </motion.div>
      </div>
    </div>
  );
};
