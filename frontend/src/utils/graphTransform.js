export const transformGraphData = (graphJson) => {
  if (!graphJson) return { nodes: [], links: [] };

  let parsed = graphJson;
  if (typeof graphJson === 'string') {
    try {
      parsed = JSON.parse(graphJson);
    } catch (e) {
      console.error("Error parsing graph JSON", e);
      return { nodes: [], links: [] };
    }
  }

  // react-force-graph expects the data to have { nodes, links }
  // Backend APIs often return { nodes, edges }, so we map edges to links if necessary
  const nodes = Array.isArray(parsed.nodes) ? parsed.nodes : [];
  
  const links = Array.isArray(parsed.links) 
    ? parsed.links 
    : Array.isArray(parsed.edges) 
      ? parsed.edges 
      : [];

  return { nodes, links };
};
