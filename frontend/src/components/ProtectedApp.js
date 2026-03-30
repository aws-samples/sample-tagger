import { Navigate,useLocation } from "react-router-dom";

export default function Protected({ children }) {
  // Authentication is disabled - allow all access
  return children;
}
