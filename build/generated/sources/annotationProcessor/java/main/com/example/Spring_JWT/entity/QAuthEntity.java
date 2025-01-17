package com.example.Spring_JWT.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QAuthEntity is a Querydsl query type for AuthEntity
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QAuthEntity extends EntityPathBase<AuthEntity> {

    private static final long serialVersionUID = -1963226386L;

    public static final QAuthEntity authEntity = new QAuthEntity("authEntity");

    public final StringPath expiration = createString("expiration");

    public final NumberPath<Long> id = createNumber("id", Long.class);

    public final StringPath refreshToken = createString("refreshToken");

    public final StringPath username = createString("username");

    public QAuthEntity(String variable) {
        super(AuthEntity.class, forVariable(variable));
    }

    public QAuthEntity(Path<? extends AuthEntity> path) {
        super(path.getType(), path.getMetadata());
    }

    public QAuthEntity(PathMetadata metadata) {
        super(AuthEntity.class, metadata);
    }

}

