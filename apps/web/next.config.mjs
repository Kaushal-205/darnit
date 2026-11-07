// Static export only: no server, no API routes, no image optimizer.
// assetPrefix "." makes every asset URL relative ("./_next/..."), so the same build works from any
// path: Vercel, an IPFS gateway (/ipfs/<cid>/) or a local folder.
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  assetPrefix: ".",
  images: { unoptimized: true },
  reactStrictMode: true,
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  // Reproducible output: build id from the source commit, not a random value.
  generateBuildId: async () => process.env.BUILD_ID ?? "session-firewall",
  transpilePackages: ["@session-firewall/sdk"],
  webpack: (config) => {
    // Everything in one initial bundle set: no lazily fetched chunks that SRI could not cover.
    config.optimization.splitChunks = false;
    return config;
  },
};

export default nextConfig;
