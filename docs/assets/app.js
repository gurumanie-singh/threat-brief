document.addEventListener("DOMContentLoaded", () => {
  const buttons = document.querySelectorAll(".filter-btn");
  const cards = document.querySelectorAll(".article-card");

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const tag = btn.dataset.tag;

      if (btn.classList.contains("active")) {
        btn.classList.remove("active");
        cards.forEach((c) => (c.style.display = ""));
        return;
      }

      buttons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      cards.forEach((card) => {
        const cardTags = (card.dataset.tags || "").split(",");
        card.style.display = cardTags.includes(tag) ? "" : "none";
      });
    });
  });
});
