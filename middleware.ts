import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { verifyJwt } from "./lib/jwt"

// Use the environment variable directly
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-here"

// Define protected routes
const adminRoutes = ["/admin"]
const clientRoutes = ["/client"]
const authRoutes = ["/login", "/not-authorized"]

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Skip middleware for static files and API routes
  if (pathname.startsWith("/_next") || pathname.startsWith("/api") || pathname.includes(".")) {
    return NextResponse.next()
  }

  // Get the token from cookies
  const token = request.cookies.get("auth_token")?.value

  // If no token and trying to access protected route, redirect to login
  if (!token) {
    if (
      adminRoutes.some((route) => pathname.startsWith(route)) ||
      clientRoutes.some((route) => pathname.startsWith(route))
    ) {
      return NextResponse.redirect(new URL("/login", request.url))
    }
    return NextResponse.next()
  }

  // Verify the token
  const { valid, payload } = verifyJwt(token, JWT_SECRET)

  if (!valid || !payload) {
    // Invalid token, redirect to login
    if (
      adminRoutes.some((route) => pathname.startsWith(route)) ||
      clientRoutes.some((route) => pathname.startsWith(route))
    ) {
      return NextResponse.redirect(new URL("/login", request.url))
    }
    return NextResponse.next()
  }

  // Check role-based access
  const { role } = payload

  // Admin trying to access client routes
  if (role === "ADMIN" && clientRoutes.some((route) => pathname.startsWith(route))) {
    return NextResponse.redirect(new URL("/not-authorized", request.url))
  }

  // Client trying to access admin routes
  if (role === "CLIENT" && adminRoutes.some((route) => pathname.startsWith(route))) {
    return NextResponse.redirect(new URL("/not-authorized", request.url))
  }

  return NextResponse.next()
}

