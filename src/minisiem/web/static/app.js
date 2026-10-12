"use strict";
const byId = id => document.getElementById(id);
const utc = value => value + "Z";
const now = new Date();
byId("end").value = now.toISOString().slice(0, 19);
byId("start").value = new Date(now.getTime()-86400000).toISOString().slice(0, 19);
let key = "";
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {"X-API-Key":key, ...options.headers}});
  if (!response.ok) throw new Error("Request failed: " + response.status);
  return response;
}
byId("search").addEventListener("submit", async event => {
  event.preventDefault(); key = byId("key").value || key; byId("key").value = "";
  try {
    const query = new URLSearchParams({start:utc(byId("start").value), end:utc(byId("end").value), q:byId("query").value});
    byId("results").innerHTML = await (await api("/v1/dashboard?"+query)).text();
    byId("error").textContent = "";
  } catch (error) { byId("error").textContent = error.message; }
});
byId("results").addEventListener("click", async event => {
  const button = event.target.closest("button.alert");
  if (!button) return;
  try { byId("detail").innerHTML = await (await api("/v1/dashboard/alerts/"+encodeURIComponent(button.dataset.id))).text(); }
  catch (error) { byId("error").textContent = error.message; }
});
byId("detail").addEventListener("submit", async event => {
  event.preventDefault();
  const form=event.target;
  const body={status:byId("status").value,notes:byId("notes").value,reason:byId("reason").value||null,until:byId("until").value ? utc(byId("until").value) : null};
  try {
    await api("/v1/alerts/"+encodeURIComponent(form.dataset.id), {method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    byId("detail").innerHTML = await (await api("/v1/dashboard/alerts/"+encodeURIComponent(form.dataset.id))).text();
  } catch (error) { byId("error").textContent=error.message; }
});
