from flask import redirect, request
raise HTTPTemporaryRedirect(url)
self.authorize_redirect(url)
return redirect("/home")
return redirect(request.args.get("next"))
