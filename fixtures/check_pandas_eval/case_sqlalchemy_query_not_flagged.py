from flask import request


def rows(db_session, session, model_cls, df, expr):
    db_session.query(model_cls).all()
    session.query(Topic).filter(Topic.id == 1)
    self.session.query(Project).first()
    df.query(expr)
    df.query(request.args["q"])
    df.eval("a + b")
