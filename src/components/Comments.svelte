<script lang="ts">
  import Giscus, { type Theme } from "@giscus/svelte";
  import { GISCUS } from "../config";
  import { getStoredTheme } from "@utils/setting-utils";
  import { onMount, onDestroy } from "svelte";

  // Props
  export let lightTheme: Theme = "https://jsdelivr.oathblade.com/gh/KinhoLeung/Oathblade/light_protanopia.css";
  export let darkTheme: Theme = "https://jsdelivr.oathblade.com/gh/KinhoLeung/Oathblade/dark_protanopia.css";

  // 响应式变量
  let theme: Theme;

  // 初始化主题
  function initTheme() {
    const storedTheme = getStoredTheme();
    if (storedTheme === "auto") {
      theme = window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    } else {
      theme = storedTheme;
    }
  }

  // 主题变化处理函数
  function handleThemeChange() {
    const newTheme = getStoredTheme();
    if (newTheme === "auto") {
      theme = window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    } else {
      theme = newTheme;
    }
  }

  onMount(() => {
    initTheme();
    window.addEventListener("themeChange", handleThemeChange);
  });

  onDestroy(() => {
    window.removeEventListener("themeChange", handleThemeChange);
  });
</script>

<div class="mt-8">
  <Giscus theme={theme === "light" ? lightTheme : darkTheme} {...GISCUS} />
</div>
