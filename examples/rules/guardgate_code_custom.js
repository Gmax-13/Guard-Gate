module.exports = {
  id: "custom-no-map-render",
  severity: "low",
  message: "Custom Rule: Do not map over users array directly in HTML (example semantic rule)",
  check: function(node, ts, context) {
    // Semantic analysis: Look for PropertyAccessExpression like `users.map`
    if (ts.isPropertyAccessExpression(node)) {
      if (
        ts.isIdentifier(node.expression) &&
        node.expression.text === "users" &&
        node.name.text === "map"
      ) {
        return true;
      }
    }
    return false;
  }
};
