import React, { useEffect, useState } from "react";
import { db } from "../firebase";
import { collection, getDocs, doc, updateDoc, setDoc, deleteDoc } from "firebase/firestore";
import { UserProfile } from "../types";
import { Users, Shield, ShieldAlert, UserCheck, UserX, Loader2, Plus, Mail, Check, AlertCircle, Lock, Trash2, X, Edit2 } from "lucide-react";
import { motion } from "motion/react";
import { COMPANY_CREDENTIALS } from "../company-credentials";

interface UserManagementProps {
  currentUser: UserProfile;
  triggerAlert: (type: "success" | "error" | "info" | "warning", message: string) => void;
}

export const UserManagement: React.FC<UserManagementProps> = ({ currentUser, triggerAlert }) => {
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  
  // Add new user form state
  const [newEmail, setNewEmail] = useState("");
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "user">("user");
  const [addLoading, setAddLoading] = useState(false);

  // Deletion confirmation state
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  // Edit user form state
  const [editingUser, setEditingUser] = useState<UserProfile | null>(null);
  const [editEmail, setEditEmail] = useState("");
  const [editName, setEditName] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editRole, setEditRole] = useState<"admin" | "user">("user");
  const [editStatus, setEditStatus] = useState<"active" | "suspended">("active");
  const [editLoading, setEditLoading] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const mergedMap = new Map<string, UserProfile>();
      let fetchedFromServer = false;

      // Track deleted users locally to prevent resurrection
      let deletedEmails: string[] = [];
      try {
        const delStr = localStorage.getItem("wolast_deleted_users");
        if (delStr) deletedEmails = JSON.parse(delStr);
      } catch (e) {}

      // 1. Fetch users from central Express server API first (VPS persistent store)
      try {
        const res = await fetch("/api/users");
        if (res.ok) {
          const data = await res.json();
          if (data && Array.isArray(data.users)) {
            data.users.forEach((u: UserProfile) => {
              if (u && u.email && !deletedEmails.includes(u.email.toLowerCase())) {
                mergedMap.set(u.email.toLowerCase(), u);
              }
            });
            fetchedFromServer = true;
          }
        }
      } catch (apiErr) {
        console.warn("Server users API fetch skipped:", apiErr);
      }

      // 2. Fetch from Firestore users collection if available
      try {
        const querySnapshot = await Promise.race([
          getDocs(collection(db, "users")),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Firestore timeout")), 2500))
        ]);
        querySnapshot.forEach((docSnap) => {
          const u = docSnap.data() as UserProfile;
          if (u && u.email && !deletedEmails.includes(u.email.toLowerCase())) {
            if (!mergedMap.has(u.email.toLowerCase())) {
              mergedMap.set(u.email.toLowerCase(), u);
            }
          }
        });
      } catch (fErr) {
        console.warn("Firestore fetch skipped or timed out:", fErr);
      }

      // 3. Add local storage users
      try {
        const localUsersStr = localStorage.getItem("wolast_local_users");
        if (localUsersStr) {
          const localUsers: UserProfile[] = JSON.parse(localUsersStr);
          localUsers.forEach((u) => {
            if (u && u.email && !deletedEmails.includes(u.email.toLowerCase())) {
              if (!mergedMap.has(u.email.toLowerCase())) {
                mergedMap.set(u.email.toLowerCase(), u);
              }
            }
          });
        }
      } catch (e) {}

      // 4. Add hardcoded COMPANY_CREDENTIALS ONLY if server wasn't fetched and not deleted
      if (!fetchedFromServer) {
        for (const cred of COMPANY_CREDENTIALS) {
          const lowerEmail = cred.email.toLowerCase();
          if (!deletedEmails.includes(lowerEmail) && !mergedMap.has(lowerEmail)) {
            const syncProfile: UserProfile = {
              uid: cred.uid,
              email: cred.email,
              displayName: cred.displayName,
              role: cred.role,
              createdAt: cred.createdAt,
              status: cred.status,
              passwordHash: cred.passwordHash
            };
            mergedMap.set(lowerEmail, syncProfile);
          }
        }
      }

      const mergedList: UserProfile[] = Array.from(mergedMap.values());

      // Sort users by email
      mergedList.sort((a, b) => a.email.localeCompare(b.email));
      setUsers(mergedList);
    } catch (err) {
      console.error("Error fetching users:", err);
      triggerAlert("error", "Failed to load user accounts database.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const saveLocalUsers = (updatedUsersList: UserProfile[]) => {
    try {
      localStorage.setItem("wolast_local_users", JSON.stringify(updatedUsersList));
    } catch (e) {
      console.error("Failed to save users to localStorage:", e);
    }
  };

  const getLocalUsers = (): UserProfile[] => {
    try {
      const localUsersStr = localStorage.getItem("wolast_local_users");
      return localUsersStr ? JSON.parse(localUsersStr) : [];
    } catch (e) {
      return [];
    }
  };

  const handleToggleRole = async (user: UserProfile) => {
    if (user.uid === currentUser.uid) {
      triggerAlert("error", "You cannot change your own administrator role.");
      return;
    }

    const nextRole = user.role === "admin" ? "user" : "admin";

    // 1. Central Express server API update
    try {
      await fetch(`/api/users/${user.uid}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: nextRole })
      });
    } catch (apiErr) {
      console.warn("Server API role update error:", apiErr);
    }

    // 2. Update in local storage
    const currentLocals = getLocalUsers().filter(u => u.uid !== user.uid && u.email.toLowerCase() !== user.email.toLowerCase());
    currentLocals.push({ ...user, role: nextRole });
    saveLocalUsers(currentLocals);

    setUsers(prev => prev.map(u => u.uid === user.uid ? { ...u, role: nextRole } : u));
    triggerAlert("success", `Updated role for ${user.displayName} to ${nextRole.toUpperCase()}`);
  };

  const handleToggleStatus = async (user: UserProfile) => {
    if (user.uid === currentUser.uid) {
      triggerAlert("error", "You cannot suspend your own account.");
      return;
    }

    const nextStatus = user.status === "active" ? "suspended" : "active";

    // 1. Central Express server API update
    try {
      await fetch(`/api/users/${user.uid}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus })
      });
    } catch (apiErr) {
      console.warn("Server API status update error:", apiErr);
    }

    // 2. Update in local storage
    const currentLocals = getLocalUsers().filter(u => u.uid !== user.uid && u.email.toLowerCase() !== user.email.toLowerCase());
    currentLocals.push({ ...user, status: nextStatus });
    saveLocalUsers(currentLocals);

    setUsers(prev => prev.map(u => u.uid === user.uid ? { ...u, status: nextStatus } : u));
    triggerAlert(
      nextStatus === "suspended" ? "warning" : "success",
      `User ${user.displayName} is now ${nextStatus.toUpperCase()}`
    );
  };

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEmail.trim() || !newName.trim() || !newPassword) {
      triggerAlert("error", "Please fill in all user profile details, including password.");
      return;
    }

    setAddLoading(true);
    try {
      const cleanEmail = newEmail.trim().toLowerCase();
      let createdProfile: UserProfile | null = null;

      // 1. Call server API to create user on VPS persistent disk
      try {
        const res = await fetch("/api/users", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: cleanEmail,
            displayName: newName.trim(),
            passwordHash: newPassword,
            role: newRole
          })
        });

        const data = await res.json();
        if (res.ok && data.success && data.user) {
          createdProfile = data.user;
        } else if (data && data.error) {
          throw new Error(data.error);
        }
      } catch (apiErr: any) {
        if (apiErr.message && apiErr.message.includes("already exists")) {
          throw apiErr;
        }
        console.warn("Server API user creation failed, falling back to local creation:", apiErr);
      }

      if (!createdProfile) {
        const tempUid = `pre_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
        createdProfile = {
          uid: tempUid,
          email: cleanEmail,
          displayName: newName.trim(),
          role: newRole,
          createdAt: new Date().toISOString(),
          status: "active",
          passwordHash: newPassword
        };
      }

      // 2. Save to local storage for instant browser backup
      const currentLocals = getLocalUsers().filter(u => u.email.toLowerCase() !== createdProfile!.email.toLowerCase());
      currentLocals.push(createdProfile);
      saveLocalUsers(currentLocals);

      triggerAlert("success", `Successfully provisioned role ${newRole.toUpperCase()} for ${cleanEmail}`);
      setShowAddForm(false);
      setNewEmail("");
      setNewName("");
      setNewPassword("");
      setNewRole("user");
      fetchUsers();
    } catch (err: any) {
      console.error("Error creating user profile:", err);
      triggerAlert("error", err.message || "Failed to create user profile.");
    } finally {
      setAddLoading(false);
    }
  };

  const handleDeleteUser = async (user: UserProfile) => {
    if (user.uid === currentUser.uid) {
      triggerAlert("error", "You cannot delete your own account.");
      return;
    }

    try {
      const lowerEmail = user.email.toLowerCase();

      // 1. Remember deleted email locally so hardcoded lists never resurrect it
      try {
        const delStr = localStorage.getItem("wolast_deleted_users");
        const deletedList: string[] = delStr ? JSON.parse(delStr) : [];
        if (!deletedList.includes(lowerEmail)) {
          deletedList.push(lowerEmail);
          localStorage.setItem("wolast_deleted_users", JSON.stringify(deletedList));
        }
      } catch (e) {}

      // 2. Call server API to delete from VPS disk store
      try {
        await fetch(`/api/users/${encodeURIComponent(user.uid)}?email=${encodeURIComponent(user.email)}`, { method: "DELETE" });
      } catch (apiErr) {
        console.warn("Server API delete user error:", apiErr);
      }

      // 3. Delete from Firestore if present
      try {
        if (user.uid) {
          await deleteDoc(doc(db, "users", user.uid));
        }
        await deleteDoc(doc(db, "users", lowerEmail));
      } catch (fErr) {
        console.warn("Firestore delete user error:", fErr);
      }

      // 4. Remove from local storage
      const currentLocals = getLocalUsers().filter(u => u.uid !== user.uid && u.email.toLowerCase() !== lowerEmail);
      saveLocalUsers(currentLocals);

      setConfirmDeleteId(null);
      setUsers(prev => prev.filter(u => u.uid !== user.uid && u.email.toLowerCase() !== lowerEmail));
      triggerAlert("success", `Successfully deleted user ${user.displayName}`);

      fetchUsers();
    } catch (err) {
      console.error("Error deleting user profile:", err);
      triggerAlert("error", "Failed to delete user profile.");
    }
  };

  const handleStartEdit = (user: UserProfile) => {
    setEditingUser(user);
    setEditEmail(user.email);
    setEditName(user.displayName);
    setEditPassword(user.passwordHash || "");
    setEditRole(user.role);
    setEditStatus(user.status);
    setShowAddForm(false); // Close add form if open
    
    // Scroll smoothly to top where edit form will appear
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;

    if (!editEmail.trim() || !editName.trim()) {
      triggerAlert("error", "Email and name fields cannot be blank.");
      return;
    }

    setEditLoading(true);
    try {
      const updatedFields: UserProfile = {
        ...editingUser,
        email: editEmail.trim().toLowerCase(),
        displayName: editName.trim(),
      };

      if (editPassword) {
        updatedFields.passwordHash = editPassword;
      }

      const isSelf = editingUser.uid === currentUser.uid;
      if (!isSelf) {
        updatedFields.role = editRole;
        updatedFields.status = editStatus;
      }

      // 1. Send update to central Express server API
      try {
        await fetch(`/api/users/${editingUser.uid}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(updatedFields)
        });
      } catch (apiErr) {
        console.warn("Server API update profile error:", apiErr);
      }

      // 2. Update in local storage
      const currentLocals = getLocalUsers().filter(u => u.uid !== editingUser.uid && u.email.toLowerCase() !== editingUser.email.toLowerCase());
      currentLocals.push(updatedFields);
      saveLocalUsers(currentLocals);

      triggerAlert("success", `Successfully updated profile for ${editName}`);
      setEditingUser(null);

      fetchUsers();
    } catch (err) {
      console.error("Error updating user profile:", err);
      triggerAlert("error", "Failed to update user profile.");
    } finally {
      setEditLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Code-based Credentials Helper Alert */}
      <div className="bg-gradient-to-r from-blue-50/50 to-indigo-50/30 border border-blue-100 rounded-2xl p-5 flex items-start gap-4 shadow-[0_8px_30px_rgb(0,0,0,0.01)]">
        <AlertCircle className="w-4 h-4 text-blue-600 shrink-0 mt-1" />
        <div className="text-xs text-blue-800 space-y-1.5 flex-1">
          <span className="font-black uppercase tracking-widest block text-[9px] text-blue-950">
            Enterprise Configuration Active
          </span>
          <p className="leading-relaxed font-bold text-slate-700">
            This platform utilizes manual enterprise configuration for employee authentication to bypass standard console constraints.
            To **change passwords**, **register employees**, or **update names/emails**, please modify the credentials database directly:
          </p>
          <div className="pt-1.5">
            <span className="font-mono bg-blue-100/60 border border-blue-200 px-3 py-1 rounded-lg text-[9px] text-blue-900 font-black tracking-wider">
              /src/company-credentials.ts
            </span>
          </div>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-sm font-black text-slate-700 uppercase tracking-widest flex items-center gap-2">
            <Users className="w-4 h-4 text-blue-600" />
            Enterprise User Accounts
          </h2>
          <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mt-1">
            Administer employee roles, auditing access, and configure granular platform security scopes.
          </p>
        </div>

        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-5 py-2.8 rounded-xl text-xs font-black uppercase tracking-widest shadow-[0_4px_12px_rgba(37,99,235,0.18)] transition-all flex items-center gap-2 cursor-pointer border border-white/5"
        >
          <Plus className="w-4 h-4" />
          Add Authorized User
        </button>
      </div>

      {showAddForm && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white border border-slate-200/80 rounded-2xl p-6 shadow-[0_12px_40px_rgba(0,0,0,0.03)] max-w-xl"
        >
          <h3 className="text-xs font-black text-slate-700 uppercase tracking-widest mb-4 border-b border-slate-100 pb-2">
            Pre-Authorize New Team Member
          </h3>
          <form onSubmit={handleAddUser} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-3.5 w-3.5 h-3.5 text-slate-400" />
                  <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="user@enterprise.com"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-10 pr-3 py-3 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400 placeholder:font-normal"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Sarah Connor"
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400 placeholder:font-normal"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-3.5 w-3.5 h-3.5 text-slate-400" />
                  <input
                    type="password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-10 pr-3 py-3 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400 placeholder:font-normal"
                  />
                </div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-t border-slate-100 pt-5">
              <div className="flex items-center gap-4">
                <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Assign Platform Role:
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setNewRole("user")}
                    className={`px-3.5 py-2 rounded-xl text-[10px] font-black border transition-all uppercase tracking-widest cursor-pointer ${
                      newRole === "user"
                        ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100"
                    }`}
                  >
                    User
                  </button>
                  <button
                    type="button"
                    onClick={() => setNewRole("admin")}
                    className={`px-3.5 py-2 rounded-xl text-[10px] font-black border transition-all uppercase tracking-widest cursor-pointer ${
                      newRole === "admin"
                        ? "bg-slate-950 text-white border-slate-950 shadow-sm"
                        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100"
                    }`}
                  >
                    Administrator
                  </button>
                </div>
              </div>

              <div className="flex gap-2.5 w-full sm:w-auto justify-end">
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="bg-white border border-slate-200 text-slate-600 px-4 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-slate-50 cursor-pointer transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={addLoading}
                  className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-4.5 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest shadow-sm flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-all border border-white/5"
                >
                  {addLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                  Save Profile
                </button>
              </div>
            </div>
          </form>
        </motion.div>
      )}

      {editingUser && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white border border-blue-200 rounded-2xl p-6 shadow-[0_12px_40px_rgba(0,0,0,0.04)] max-w-xl"
        >
          <div className="flex justify-between items-center mb-4 border-b border-slate-100 pb-2">
            <h3 className="text-xs font-black text-blue-700 uppercase tracking-widest flex items-center gap-2">
              <Edit2 className="w-3.5 h-3.5" />
              Edit Team Member Details
            </h3>
            <button 
              onClick={() => setEditingUser(null)}
              className="text-slate-400 hover:text-slate-600 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <form onSubmit={handleSaveEdit} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-3.5 w-3.5 h-3.5 text-slate-400" />
                  <input
                    type="email"
                    required
                    value={editEmail}
                    onChange={(e) => setEditEmail(e.target.value)}
                    placeholder="user@enterprise.com"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-10 pr-3 py-3 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  placeholder="Sarah Connor"
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Password (New/Plaintext)
                </label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-3.5 w-3.5 h-3.5 text-slate-400" />
                  <input
                    type="text"
                    value={editPassword}
                    onChange={(e) => setEditPassword(e.target.value)}
                    placeholder="Leave unchanged"
                    className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-10 pr-3 py-3 text-xs focus:bg-white focus:outline-hidden focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/80 text-slate-900 font-bold transition-all placeholder:text-slate-400"
                  />
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-slate-100 pt-5">
              <div className="space-y-2">
                <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Platform Role:
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={editingUser.uid === currentUser.uid}
                    onClick={() => setEditRole("user")}
                    className={`px-3.5 py-2 rounded-xl text-[10px] font-black border transition-all uppercase tracking-widest cursor-pointer flex-1 ${
                      editingUser.uid === currentUser.uid
                        ? "opacity-40 cursor-not-allowed bg-slate-100 border-slate-200 text-slate-400"
                        : editRole === "user"
                        ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100"
                    }`}
                  >
                    User
                  </button>
                  <button
                    type="button"
                    disabled={editingUser.uid === currentUser.uid}
                    onClick={() => setEditRole("admin")}
                    className={`px-3.5 py-2 rounded-xl text-[10px] font-black border transition-all uppercase tracking-widest cursor-pointer flex-1 ${
                      editingUser.uid === currentUser.uid
                        ? "opacity-40 cursor-not-allowed bg-slate-100 border-slate-200 text-slate-400"
                        : editRole === "admin"
                        ? "bg-slate-950 text-white border-slate-950 shadow-sm"
                        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100"
                    }`}
                  >
                    Administrator
                  </button>
                </div>
                {editingUser.uid === currentUser.uid && (
                  <p className="text-[9px] text-amber-600 font-semibold mt-1">You cannot modify your own administrator role.</p>
                )}
              </div>

              <div className="space-y-2">
                <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block">
                  Account Status:
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={editingUser.uid === currentUser.uid}
                    onClick={() => setEditStatus("active")}
                    className={`px-3.5 py-2 rounded-xl text-[10px] font-black border transition-all uppercase tracking-widest cursor-pointer flex-1 ${
                      editingUser.uid === currentUser.uid
                        ? "opacity-40 cursor-not-allowed bg-slate-100 border-slate-200 text-slate-400"
                        : editStatus === "active"
                        ? "bg-emerald-600 text-white border-emerald-600 shadow-sm"
                        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100"
                    }`}
                  >
                    Active
                  </button>
                  <button
                    type="button"
                    disabled={editingUser.uid === currentUser.uid}
                    onClick={() => setEditStatus("suspended")}
                    className={`px-3.5 py-2 rounded-xl text-[10px] font-black border transition-all uppercase tracking-widest cursor-pointer flex-1 ${
                      editingUser.uid === currentUser.uid
                        ? "opacity-40 cursor-not-allowed bg-slate-100 border-slate-200 text-slate-400"
                        : editStatus === "suspended"
                        ? "bg-rose-600 text-white border-rose-600 shadow-sm"
                        : "bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100"
                    }`}
                  >
                    Suspended
                  </button>
                </div>
                {editingUser.uid === currentUser.uid && (
                  <p className="text-[9px] text-amber-600 font-semibold mt-1">You cannot modify your own account status.</p>
                )}
              </div>
            </div>

            <div className="flex justify-end gap-2.5 border-t border-slate-100 pt-5">
              <button
                type="button"
                onClick={() => setEditingUser(null)}
                className="bg-white border border-slate-200 text-slate-600 px-4 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-slate-50 cursor-pointer transition-all"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={editLoading}
                className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-4.5 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest shadow-sm flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-all border border-white/5"
              >
                {editLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                Save Changes
              </button>
            </div>
          </form>
        </motion.div>
      )}

      <div className="bg-white border border-slate-200/80 rounded-2xl overflow-hidden shadow-[0_8px_30px_rgb(0,0,0,0.02)]">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-2">
            <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
            <span className="text-xs font-semibold">Loading user profiles database...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50/50 border-b border-slate-200 text-slate-500 font-black uppercase tracking-widest text-[9px]">
                  <th className="py-4 px-5">User Details</th>
                  <th className="py-4 px-5">Email / Auth Method</th>
                  <th className="py-4 px-5">Platform Role</th>
                  <th className="py-4 px-5">Account Status</th>
                  <th className="py-4 px-5">Registered Date</th>
                  <th className="py-4 px-5 text-right">Administrative Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-semibold text-slate-700">
                {users.map((user) => {
                  const isSelf = user.uid === currentUser.uid;
                  return (
                    <tr key={user.uid} className="hover:bg-slate-50/40 transition-colors">
                      <td className="py-4 px-5">
                        <div className="font-black text-slate-900 flex items-center gap-2">
                          {user.displayName}
                          {isSelf && (
                            <span className="bg-blue-50 text-blue-700 text-[9px] px-2 py-0.5 rounded-lg border border-blue-100 font-extrabold uppercase tracking-wider">
                              Self
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-4 px-5 font-mono text-[11px] text-slate-500">
                        {user.email}
                      </td>
                      <td className="py-4 px-5">
                        {user.role === "admin" ? (
                          <span className="inline-flex items-center gap-1 text-slate-900 bg-slate-50 border border-slate-200 px-2.5 py-0.8 rounded-lg font-black text-[9px] uppercase tracking-wider">
                            <Shield className="w-3 h-3 text-slate-700" />
                            Admin
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-blue-800 bg-blue-50/40 border border-blue-100 px-2.5 py-0.8 rounded-lg font-black text-[9px] uppercase tracking-wider">
                            User
                          </span>
                        )}
                      </td>
                      <td className="py-4 px-5">
                        {user.status === "active" ? (
                          <span className="inline-flex items-center gap-1 text-emerald-700 bg-emerald-50/40 border border-emerald-100 px-2.5 py-0.8 rounded-lg font-black text-[9px] uppercase tracking-wider">
                            <UserCheck className="w-3 h-3" />
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-700 bg-rose-50/40 border border-rose-100 px-2.5 py-0.8 rounded-lg font-black text-[9px] uppercase tracking-wider">
                            <UserX className="w-3 h-3" />
                            Suspended
                          </span>
                        )}
                      </td>
                      <td className="py-4 px-5 text-slate-500 font-bold">
                        {new Date(user.createdAt).toLocaleDateString()}
                      </td>
                      <td className="py-4 px-5">
                        <div className="flex justify-end gap-2.5">
                          <button
                            onClick={() => handleStartEdit(user)}
                            className="bg-white border-slate-200 hover:border-slate-300 hover:bg-blue-50/40 hover:text-blue-700 text-blue-600 px-3 py-1.5 text-[9px] font-black rounded-lg border shadow-2xs transition-all uppercase tracking-widest cursor-pointer flex items-center gap-1"
                            title="Edit user profile"
                          >
                            <Edit2 className="w-2.5 h-2.5" />
                            Edit
                          </button>
                          <button
                            onClick={() => handleToggleRole(user)}
                            disabled={isSelf}
                            className={`px-3 py-1.5 text-[9px] font-black rounded-lg border shadow-2xs transition-all uppercase tracking-widest cursor-pointer ${
                              isSelf
                                ? "opacity-30 cursor-not-allowed bg-slate-100 border-slate-200 text-slate-400 shadow-none"
                                : "bg-white border-slate-200 hover:border-slate-300 text-slate-700"
                            }`}
                          >
                            Toggle Role
                          </button>
                          <button
                            onClick={() => handleToggleStatus(user)}
                            disabled={isSelf}
                            className={`px-3 py-1.5 text-[9px] font-black rounded-lg border shadow-2xs transition-all uppercase tracking-widest cursor-pointer ${
                              isSelf
                                ? "opacity-30 cursor-not-allowed bg-slate-100 border-slate-200 text-slate-400 shadow-none"
                                : user.status === "active"
                                ? "bg-rose-50/30 border-rose-100 text-rose-700 hover:bg-rose-100/60"
                                : "bg-emerald-50/30 border-emerald-100 text-emerald-700 hover:bg-emerald-100/60"
                            }`}
                          >
                            {user.status === "active" ? "Suspend" : "Activate"}
                          </button>

                          {confirmDeleteId === user.uid ? (
                            <div className="flex items-center gap-1 bg-rose-50 border border-rose-200/60 p-1 rounded-lg">
                              <span className="text-[8px] font-black text-rose-700 uppercase tracking-wider px-1">
                                Confirm?
                              </span>
                              <button
                                onClick={() => handleDeleteUser(user)}
                                className="bg-rose-600 hover:bg-rose-700 text-white p-1 rounded-md text-[9px] font-black uppercase tracking-widest cursor-pointer transition-all flex items-center justify-center"
                                title="Permanently delete user"
                              >
                                <Check className="w-3 h-3" />
                              </button>
                              <button
                                onClick={() => setConfirmDeleteId(null)}
                                className="bg-slate-200 hover:bg-slate-300 text-slate-700 p-1 rounded-md text-[9px] font-black uppercase tracking-widest cursor-pointer transition-all flex items-center justify-center"
                                title="Cancel deletion"
                              >
                                <X className="w-3 h-3" />
                              </button>
                            </div>
                          ) : (
                            <button
                              onClick={() => setConfirmDeleteId(user.uid)}
                              disabled={isSelf}
                              className={`px-3 py-1.5 text-[9px] font-black rounded-lg border shadow-2xs transition-all uppercase tracking-widest cursor-pointer flex items-center gap-1 ${
                                isSelf
                                  ? "opacity-30 cursor-not-allowed bg-slate-100 border-slate-200 text-slate-400 shadow-none"
                                  : "bg-white border-slate-200 hover:bg-rose-50 hover:text-rose-700 hover:border-rose-200 text-slate-600"
                              }`}
                            >
                              <Trash2 className="w-3 h-3" />
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
