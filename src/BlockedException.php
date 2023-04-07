<?php

namespace kozlovsv\jwtauth;
use UnexpectedValueException;

/**
 * Exception throws if token not in WhiteList
 */
class BlockedException extends UnexpectedValueException
{
}
