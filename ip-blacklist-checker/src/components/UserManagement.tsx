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
      const querySnapshot = await getDocs(collection(db, "users"));
      const firestoreUsersMap = new Map<string, UserProfile>();
      
      querySnapshot.forEach((docSnap) => {
        const u = docSnap.data() as UserProfile;
        firestoreUsersMap.set(u.email.toLowerCase(), u);
      });

      // Merge offline COMPANY_CREDENTIALS to ensure they are visible and synchronized in Firestore
      const mergedList: UserProfile[] = [];
      
      // 1. Add all Firestore users
      firestoreUsersMap.forEach((user) => {
        mergedList.push(user);
      });

      // 2. Add any hardcoded COMPANY_CREDENTIALS that are not in Firestore yet
      for (const cred of COMPANY_CREDENTIALS) {
        const lowerEmail = cred.email.toLowerCase();
        if (!firestoreUsersMap.has(lowerEmail)) {
          const syncProfile: UserProfile = {
            uid: cred.uid,
            email: cred.email,
            displayName: cred.displayName,
            role: cred.role,
            createdAt: cred.createdAt,
            status: cred.status,
            passwordHash: cred.passwordHash
          };
          mergedList.push(syncProfile);
          // Sync to Firestore so the user's role can be dynamically updated/modified/deleted
          await setDoc(doc(db, "users", cred.uid), syncProfile);
        }
      }

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

  const handleToggleRole = async (user: UserProfile) => {
    if (user.uid === currentUser.uid) {
      triggerAlert("error", "You cannot change your own administrator role.");
      return;
    }

    const nextRole = user.role === "admin" ? "user" : "admin";
    try {
      await updateDoc(doc(db, "users", user.uid), { role: nextRole });
      triggerAlert("success", `Updated role for ${user.displayName} to ${nextRole.toUpperCase()}`);
      setUsers(prev => prev.map(u => u.uid === user.uid ? { ...u, role: nextRole } : u));
    } catch (err) {
      console.error("Error updating role:", err);
      triggerAlert("error", "Failed to update user role.");
    }
  };

  const handleToggleStatus = async (user: UserProfile) => {
    if (user.uid === currentUser.uid) {
      triggerAlert("error", "You cannot suspend your own account.");
      return;
    }

    const nextStatus = user.status === "active" ? "suspended" : "active";
    try {
      await updateDoc(doc(db, "users", user.uid), { status: nextStatus });
      triggerAlert(
        nextStatus === "suspended" ? "warning" : "success",
        `User ${user.displayName} is now ${nextStatus.toUpperCase()}`
      );
      setUsers(prev => prev.map(u => u.uid === user.uid ? { ...u, status: nextStatus } : u));
    } catch (err) {
      console.error("Error updating status:", err);
      triggerAlert("error", "Failed to update user account status.");
    }
  };

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEmail.trim() || !newName.trim() || !newPassword) {
      triggerAlert("error", "Please fill in all user profile details, including password.");
      return;
    }

    setAddLoading(true);
    try {
      // Create a virtual user doc in firestore so when they register, their role is already set
      // Generate a deterministic or random UID for pre-seeding
      const tempUid = `pre_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      
      const newProfile: UserProfile = {
        uid: tempUid,
        email: newEmail.trim().toLowerCase(),
        displayName: newName.trim(),
        role: newRole,
        createdAt: new Date().toISOString(),
        status: "active",
        passwordHash: newPassword
      };

      await setDoc(doc(db, "users", tempUid), newProfile);
      triggerAlert("success", `Successfully provisioned role ${newRole.toUpperCase()} for ${newEmail}`);
      setShowAddForm(false);
      setNewEmail("");
      setNewName("");
      setNewPassword("");
      setNewRole("user");
      fetchUsers();
    } catch (err) {
      console.error("Error creating user profile:", err);
      triggerAlert("error", "Failed to pre-seed user profile.");
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
      await deleteDoc(doc(db, "users", user.uid));
      triggerAlert("success", `Successfully deleted user ${user.displayName}`);
      setConfirmDeleteId(null);
      fetchUsers();
    } catch (err) {
      console.error("Error deleting user:", err);
      triggerAlert("error", "Failed to delete user account.");
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
      const updatedFields: Partial<UserProfile> = {
        email: editEmail.trim().toLowerCase(),
        displayName: editName.trim(),
      };

      // Only update password if user entered/changed it
      if (editPassword) {
        updatedFields.passwordHash = editPassword;
      }

      // Restrict role/status changes for self
      const isSelf = editingUser.uid === currentUser.uid;
      if (!isSelf) {
        updatedFields.role = editRole;
        updatedFields.status = editStatus;
      }

      await updateDoc(doc(db, "users", editingUser.uid), updatedFields);
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
