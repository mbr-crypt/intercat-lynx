"""Account deletion that also removes the data pointing at the account."""

from sqlalchemy.orm import Session

from ..models import (
    Bookmark,
    Comment,
    CommentVote,
    CVEVote,
    EmailVerification,
    Notification,
    User,
)


def _comment_tree_ids(db: Session, user_id: int) -> list:
    """Ids of all comments of the user plus every reply below them."""
    ids = [row[0] for row in db.query(Comment.id).filter(Comment.user_id == user_id).all()]
    seen = set(ids)
    frontier = list(ids)
    while frontier:
        children = [
            row[0]
            for row in db.query(Comment.id).filter(Comment.parent_id.in_(frontier)).all()
            if row[0] not in seen
        ]
        seen.update(children)
        frontier = children
    return list(seen)


def delete_user_and_data(db: Session, user: User) -> None:
    """
    Delete the account. The database has no cascading rules for most tables, so
    the dependent rows are removed here first (otherwise PostgreSQL refuses the
    delete). Tech stacks are removed by the database (ON DELETE CASCADE).

    Removed: bookmarks, votes, notifications received, the user's comments
    including replies below them. Kept but detached: notifications the user
    triggered for others, e-mail verification records.
    """
    comment_ids = _comment_tree_ids(db, user.id)
    if comment_ids:
        db.query(CommentVote).filter(CommentVote.comment_id.in_(comment_ids)).delete(
            synchronize_session=False
        )
        # replies first: break the parent links, then delete
        db.query(Comment).filter(Comment.id.in_(comment_ids)).update(
            {Comment.parent_id: None}, synchronize_session=False
        )
        db.query(Comment).filter(Comment.id.in_(comment_ids)).delete(synchronize_session=False)

    db.query(CommentVote).filter(CommentVote.user_id == user.id).delete(synchronize_session=False)
    db.query(CVEVote).filter(CVEVote.user_id == user.id).delete(synchronize_session=False)
    db.query(Bookmark).filter(Bookmark.user_id == user.id).delete(synchronize_session=False)
    db.query(Notification).filter(Notification.user_id == user.id).delete(synchronize_session=False)
    db.query(Notification).filter(Notification.actor_id == user.id).update(
        {Notification.actor_id: None}, synchronize_session=False
    )
    db.query(EmailVerification).filter(EmailVerification.user_id == user.id).update(
        {EmailVerification.user_id: None}, synchronize_session=False
    )
    db.delete(user)
