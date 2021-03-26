# Fetch a cookie from a local browser's cookie store

**DON'T USE THIS CRATE** for anything you ship to users or need to support in a long-term!

This crate relies on undocumented, unsupported internal implementation of browsers and could break
at any time. It is only good for a quick-n-dirty local scripting and automation, when you want to drive
some API that does not provide means to get a long-lived, stable token and the browser cookie is the
only way to go.

Note that this crate's license is GPL v3, specifically because I think that commercial use of this crate
is a terrible idea.
