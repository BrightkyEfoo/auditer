/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@auditer/types"],
  async rewrites() {
    // Proxy API + SSE to the NestJS api so the browser talks same-origin.
    const api = process.env.API_URL ?? "http://localhost:3001";
    return [{ source: "/api/:path*", destination: `${api}/api/:path*` }];
  },
};

export default nextConfig;
