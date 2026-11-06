import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = "https://vibecheck.dev";
  const routes = [
    { path: "", priority: 1 },
    { path: "/platform", priority: 0.9 },
    { path: "/how-it-works", priority: 0.8 },
    { path: "/integrations", priority: 0.7 },
    { path: "/developers", priority: 0.8 },
    { path: "/pricing", priority: 0.6 },
    { path: "/about", priority: 0.6 },
  ];

  return routes.map((route) => ({
    url: `${base}${route.path}`,
    lastModified: new Date(),
    changeFrequency: "monthly" as const,
    priority: route.priority,
  }));
}
